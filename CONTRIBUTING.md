# Contributing to cleave

Thanks for your interest in contributing! Whether you're writing your first detection rule or submitting a complex engine feature, we're glad you're here.

cleave is hosted on GitHub. We accept contributions via pull requests.

## Getting Started

```bash
git clone <repo-url>
cd cleave
make build
make test
```

Optional tools that make life easier:
- [rizin](https://github.com/rizinorg/rizin) — binary reverse engineering support
- [cargo-nextest](https://nexte.st/) — faster parallel test runs

If you run into trouble building, open an issue and we'll help you sort it out.

## Writing Detection Rules

The easiest way to contribute is by adding traits — the YAML detection rules that make cleave useful. No Rust knowledge required.

Traits live in `traits/` under four tiers:

| Tier | Path | What belongs here |
|------|------|-------------------|
| Capabilities | `micro-behaviors/` | A single observable capability (never `hostile`) |
| Objectives | `objectives/` | Attacker intent inferred from combining capabilities |
| Known Entities | `well-known/` | Specific malware family or tool signatures |
| Metadata | `metadata/` | Informational file properties |

If you're unsure where a rule belongs, the decision framework in [TAXONOMY.md](./TAXONOMY.md) will walk you through it. For YAML syntax, condition types, and composite rules, see [RULES.md](./RULES.md). For precision scoring (hostile composites need >= 3.5), see [PRECISION.md](./PRECISION.md).

### Step by step

1. **Find the right directory** using the taxonomy tree in [TAXONOMY.md](./TAXONOMY.md) — for example, `traits/micro-behaviors/crypto/hash/`
2. **Add or edit a `.yaml` file** in that directory. Here's a minimal example:

   ```yaml
   # traits/micro-behaviors/crypto/hash/ruby.yaml
   defaults:
     for: [ruby]
     crit: notable

   traits:
     - id: sha256
       desc: SHA-256 hash computation
       conf: 0.9
       mbc: "C0029"
       if:
         type: symbol
         kind: call
         substr: "Digest::SHA256"
   ```

   Trait IDs are auto-prefixed by directory path, so this produces `micro-behaviors/crypto/hash::sha256`.

3. **Test against a real sample:**
   ```bash
   cleave test-rules /path/to/sample --rules "your-trait-id"
   cleave test-match /path/to/sample --type text --pattern "your-pattern"
   ```

   Use `--type text` for most human-readable patterns. Use `--type literal`
   for parser-extracted string and number literals from source files
   (formerly `string-literal`, kept as a serde alias).

4. **Run the checks:**
   ```bash
   make test      # full test suite
   make test-fast # quick feedback (skips YARA, lib tests only)
   make lint      # formatting + clippy + unused dependency check
   ```

Don't have a good malware sample to test against? Mention that in your PR — reviewers can help validate.

## Bug Fixes and Features

For changes to the Rust codebase under `src/`:

1. Read the relevant source and understand what you're changing
2. Write or update tests for your change
3. Make sure everything passes:
   ```bash
   make ci   # runs test + lint together
   ```

All compiler warnings must be clean. If you're not sure about the right approach, open an issue first to discuss — we'd rather help you find the right direction early than have you spend time on something that needs a big rework.

## Pull Request Checklist

- [ ] `make ci` passes
- [ ] New traits follow [TAXONOMY.md](./TAXONOMY.md) placement and tier dependency rules
- [ ] Composite rules meet [PRECISION.md](./PRECISION.md) thresholds
- [ ] Hostile rules live in `objectives/` or `well-known/`, never in `micro-behaviors/`
- [ ] Tested against at least one real sample with `cleave test-rules`

## Questions?

If anything is unclear or you'd like guidance before starting, open an issue. There are no bad questions — we'd rather help you get started than have you stuck in silence.

## License

Contributions are under [Apache-2.0](./LICENSE). By submitting a PR, you agree to license your work under the same terms.
