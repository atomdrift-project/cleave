# flayer Rule Writing Guide

## Quick Overview

**Traits** = atomic observations (single pattern)
**Composites** = traits combined via boolean logic
**Criticality** = independent from confidence

**Tier hierarchy:**
- `micro-behaviors/*` - Observable capabilities (what code can do)
- `objectives/*` - Attacker objectives (intent signals)
- `well-known/*` - Specific malware/tool signatures (family-unique only)
- `metadata/*` - Informational file properties

See [TAXONOMY.md](./TAXONOMY.md) for complete tier structure.

**Tier dependencies:**
- `micro-behaviors/` → can reference `micro-behaviors/` and `metadata/` only
- `objectives/` → can reference `micro-behaviors/`, `objectives/`, and `metadata/`
- `well-known/` → can reference `micro-behaviors/`, `objectives/`, `well-known/`, and `metadata/`
- `metadata/` → typically references `metadata/` only

**Critical rules:**
- `micro-behaviors/` must NOT reference `objectives/` (capabilities are atomic, objectives infer intent)
- `micro-behaviors/` must NOT use `crit: hostile` (hostile requires intent inference, belongs in `objectives/`)

## Trait Placement & IDs

- IDs auto-prefixed by directory path (e.g., `traits/micro-behaviors/process/create/shell/` → prefix `micro-behaviors/process/create/shell`)
- **Filenames are NEVER part of trait IDs** - only the directory path is used for prefixing
  - A trait `foo` in `traits/micro-behaviors/process/create/shell/python.yaml` has ID `micro-behaviors/process/create/shell::foo`
  - NOT `micro-behaviors/process/create/shell/python::foo` or `micro-behaviors/process/create/shell/python/foo`
- Cross-tier references use full paths: `micro-behaviors/process/create/shell::subprocess`
- Directory match: `micro-behaviors/process/create/shell/` matches all traits in that directory
- Generic capabilities NEVER go in `well-known/`

## Criticality Levels

| Level | Use When |
|-------|----------|
| `component` | Building blocks that make no sense individually (string fragments like `&cc=`) |
| `baseline` | Common functionality that doesn't describe program purpose (`mmap`, `stdio`, `read`) |
| `notable` | Defines program purpose (`socket`, `exec`, `eval`, `sysctl`) |
| `suspicious` | Hides intent/crosses boundaries (VM detection, obfuscation) |
| `hostile` | Attack patterns, no legitimate use (reverse shell, ransomware) |

Both `component` and `baseline` are allowed in any tier.

**Component traits** are filtered from terminal output unless a composite rule that references them fires. JSON output always includes all components for ML signal.

**HOSTILE composites require precision ≥ 3.5**, else downgraded. See [PRECISION.md](./PRECISION.md) for the calculation algorithm and authoring guidelines.

## Trait Definition

```yaml
traits:
  - id: execution/terminate          # ID relative to directory
    desc: Process termination API call   # 4-6 words, what was detected
    crit: suspicious                     # baseline|notable|suspicious|hostile
    conf: 0.95                           # 0.0-1.0
    mbc: "E1562"                         # Optional MBC code
    attack: "T1562"                      # Optional ATT&CK code
    for: [csharp]                        # File types (see below)
    platforms: [linux, macos, windows]   # Optional platform filter
    size_min: 1000                       # Optional min file size (bytes)
    size_max: 10485760                   # Optional max file size
    entropy_min: 4.5                     # Optional min file entropy (0.0-8.0; section entropy handled via type: section)
    entropy_max: 7.5                     # Optional max file entropy
    if:                                  # Condition (see below)
      type: string
      substr: ".Kill("
```

**File types:** `elf`, `macho`, `pe`, `dll`, `so`, `dylib`, `shell`, `batch`, `python`, `javascript`, `typescript`, `rust`, `java`, `class`, `ruby`, `c`, `cpp`, `go`, `csharp`, `php`, `perl`, `powershell`, `lua`, `swift`, `objectivec`, `groovy`, `scala`, `zig`, `elixir`, `vbs`, `html`, `applescript`, `packagejson`, `chrome-manifest`, `cargo-toml`, `pyproject-toml`, `github-actions`, `composer-json`, `plist`, `ipa`, `text`, `rtf`, `all`.

**Groups:** `binaries` (or `binary`), `scripts` (or `script`, `scripting`).
**Exclusions:** Prefix with `-` (e.g., `-php`, `scripts,-python`).

## Condition Types

### Pattern Matching

| Type | Purpose | Matchers | Modifiers |
|------|---------|----------|-----------|
| `string` | Extracted strings | `exact`, `substr`, `regex`, `word` | count, density, location, `case_insensitive`, `external_ip` |
| `raw` | Raw file bytes | `exact`, `substr`, `regex`, `word` | count, density, location, `case_insensitive`, `external_ip` |
| `symbol` | Imports/exports | `exact`, `substr`, `regex` | `platforms` |
| `hex` | Byte patterns (wildcards always extracted) | pattern string | count, density, `offset`, `offset_range` |
| `encoded` | **All decoded strings** | `exact`, `substr`, `regex`, `word` | count, density, location, `encoding`, `case_insensitive` |
| `base64` | Base64-decoded *(deprecated - use `encoded`)* | `exact`, `substr`, `regex` | count, density, location, `case_insensitive` |
| `xor` | XOR-decoded *(deprecated - use `encoded`)* | `exact`, `substr`, `regex` | count, density, location, `key`, `case_insensitive` |
| `kv` | Manifest data | `exact`, `substr`, `regex` | `path`, `case_insensitive` |
| `basename` | Filename | `exact`, `substr`, `regex` | `case_insensitive` |

### Structural

| Type | Purpose | Fields |
|------|---------|--------|
| `ast` | Parse source | `kind`/`node`, `exact`/`substr`/`regex`/`query` |
| `syscall` | Direct syscalls | `name`, `number`, `arch`, `count_min`, `count_max`, `per_kb_min`, `per_kb_max` |
| `section` | Binary sections | `exact`, `substr`, `regex`, `word`, `case_insensitive`, `length_min`, `length_max`, `entropy_min`, `entropy_max`, `readable`, `writable`, `executable` |
| `section_ratio` | Section size ratio | `section`, `compare_to`, `min`, `max` |
| `import_combination` | Import patterns | `required`, `suspicious`, `min_suspicious` |
| `metrics` | Code metrics | `field`, `min`, `max`, `min_size` |
| `trait_glob` | Match traits | `pattern`, `match` (any/all/N) |
| `filesize` | File size | `min`, `max` |
| `yara` | YARA rule | `source` |

### Hex Pattern Syntax

| Token | Description | Example |
|-------|-------------|---------|
| `XX` | Literal byte (hex) | `7F 45 4C 46` |
| `??` | Any single byte (wildcard) | `31 ?? 48` |
| `X?` | High nibble fixed, low nibble wild | `4?` matches 0x40-0x4F |
| `?X` | Low nibble fixed, high nibble wild | `?A` matches any byte ending in A |
| `[N]` | Skip exactly N bytes | `00 [4] FF` |
| `[N-M]` | Skip N to M bytes | `00 [2-8] FF` |
| `(XX\|YY)` | Byte alternation (match any) | `(00\|80)` matches 0x00 or 0x80 |

**Examples:**

```yaml
# ELF magic
if:
  type: hex
  pattern: "7F 45 4C 46"

# XOR loop detection (nibble wildcards for register variants)
if:
  type: hex
  pattern: "31 ?? 88 ?? 4? 83 ?? ?? 7?"

# LZMA header with size byte options
if:
  type: hex
  pattern: "5D 00 00 (00|80) 00 (01|02|03|04) [7] ??"
```

### AST Kinds

`call`, `function`, `class`, `import`, `string`, `comment`, `assignment`, `return`, `binary_op`, `identifier`, `attribute`, `subscript`, `conditional`, `loop`

## Count & Density Constraints

Available on `string`, `raw`, `hex`, `encoded`, `base64`, `xor`:

| Field | Description |
|-------|-------------|
| `count_min` | Minimum matches required (default: 1) |
| `count_max` | Maximum matches allowed |
| `per_kb_min` | Minimum matches per KB |
| `per_kb_max` | Maximum matches per KB |

```yaml
- id: dense-chr-calls
  if:
    type: raw
    regex: "chr\\s*\\("
    count_min: 10
    per_kb_min: 2.0
```

## Location Constraints

Available on `string`, `raw`, `encoded`, `base64`, `xor`. Hex supports `offset` and `offset_range`.

| Field | Description |
|-------|-------------|
| `section` | Restrict to named section (fuzzy: `text` → `.text`, `__text`) |
| `offset` | Exact file offset (negative = from end) |
| `offset_range` | `[start, end)` range (`null` = open-ended) |
| `section_offset` | Offset within section (requires `section`) |
| `section_offset_range` | Range within section (requires `section`) |

```yaml
# Last 1KB of file
- id: trailer-check
  if:
    type: string
    substr: "END"
    offset_range: [-1024, null]

# First 64 bytes (magic/header)
- id: magic-check
  if:
    type: hex
    pattern: "7F 45 4C 46"
    offset: 0
```

## Section Constraints

### Size Constraints

The `section` condition type supports absolute size constraints to detect structural anomalies:

```yaml
# Detect abnormally small __cstring section (string obfuscation)
- id: tiny-cstring-absolute
  desc: Abnormally small __cstring section
  crit: suspicious
  conf: 0.85
  for: [macho]
  size_min: 100000  # Only check binaries >100KB
  if:
    type: section
    exact: "__TEXT.____cstring"
    length_max: 100  # Section must be ≤100 bytes

# Detect large __data section (encoded payload storage)
- id: large-data-payload
  desc: Large __DATA section (8KB+)
  crit: notable
  conf: 0.75
  for: [macho]
  if:
    type: section
    exact: "__DATA.____data"
    length_min: 8192  # Section must be ≥8KB

# Detect section in specific size range
- id: suspicious-section-size
  desc: Section with suspicious size
  crit: suspicious
  conf: 0.8
  if:
    type: section
    substr: ".data"
    length_min: 8192
    length_max: 16384  # Between 8KB and 16KB
```

**Size constraints:**
- `length_min` - Minimum section length in bytes
- `length_max` - Maximum section length in bytes
- Can be used alone or combined with name patterns
- Evidence includes section size in output

### Permission Constraints

Filter sections by permission flags (PE/ELF/Mach-O):

| Field | Match Behavior |
|-------|----------------|
| `readable: true` | Section contains 'r' in permissions string |
| `writable: true` | Section contains 'w' in permissions string |
| `executable: true` | Section contains 'x' in permissions string |

Adds +0.5 precision per constraint. Combinable with entropy/size/name filters.

```yaml
# Packing detection
type: section
executable: true
entropy_min: 7.0

# W^X violation
type: section
writable: true
executable: true

# Obfuscated writable data
type: section
regex: "^(\\.data|__data)"
writable: true
entropy_min: 6.5
```

## Encoded Strings

The `encoded` type searches decoded/encoded strings with optional encoding filter. It unifies and replaces the deprecated `base64` and `xor` types with additional features:

- **Word boundary matching**: `word` parameter (not available in `base64`/`xor`)
- **Flexible encoding filter**: Single, multiple (OR), or omit (all)
- **Supports all encoding types**: base64, base64-obf, hex, xor, url, unicode-escape, stack, wide

### Encoding Filter

| Syntax | Behavior | Example |
|--------|----------|---------|
| Omit `encoding:` | Search **all** encoded strings | `type: encoded, substr: "eval"` |
| Single string | Search single encoding type | `encoding: base64` |
| Array | Search multiple types (OR) | `encoding: [base64, hex]` |

### Examples

```yaml
# Search ALL encoded strings for "password"
- id: encoded-password
  if:
    type: encoded
    word: password    # Word boundary match (NEW!)

# Search only base64 strings
- id: base64-url
  if:
    type: encoded
    encoding: base64
    regex: "https?://"

# Search base64 OR hex for suspicious patterns
- id: multi-encoding-check
  if:
    type: encoded
    encoding: [base64, hex]
    substr: "cmd.exe"
    count_min: 2

# Case-insensitive search in XOR-decoded strings
- id: xor-malware
  if:
    type: encoded
    encoding: xor
    substr: MALWARE
    case_insensitive: true

# Density check across all encoded strings
- id: dense-encoded
  if:
    type: encoded
    substr: eval
    count_min: 5
    per_kb_min: 3.0
```

### Migration from base64/xor

Replace deprecated types:

```yaml
# OLD (deprecated)
type: base64
substr: "secret"

# NEW (recommended)
type: encoded
encoding: base64
substr: "secret"

# OLD (deprecated)
type: xor
regex: "malware"

# NEW (recommended)
type: encoded
encoding: xor
regex: "malware"
```

**Advantage**: Use `encoded` without `encoding:` to search *all* decoded strings regardless of encoding type.

## Composite Rules

```yaml
composite_rules:
  - id: reverse-shell
    desc: Reverse shell pattern
    crit: hostile
    conf: 0.95
    for: [elf, macho]
    all:                              # AND (all must match)
      - id: micro-behaviors/communications/socket/create
      - id: micro-behaviors/process/fd/dup2
      - id: micro-behaviors/process/create/shell
    any:                              # OR (at least one)
      - id: pattern-a
      - id: pattern-b
    none:                             # NOT (none may match)
      - id: legitimate-use
    needs: 2                          # Min matches from `any:`
```

## Trait References in `if:`

Atomic traits can reference other traits via `if: id:`. This creates a **derived trait** that fires when the referenced trait matches. This is a hybrid between atomic traits and composites.

```yaml
traits:
  # Derived trait: adds section constraint to existing pattern
  - id: base64-in-rodata
    desc: Base64 data in rodata section
    crit: notable                    # Can change criticality
    if:
      id: objectives/anti-static/obfuscation/encoding/base64::dense-base64-encoding
      section: rodata                # Add section constraint
      count_min: 10                  # Add count constraint
```

### When to Use Trait References

**Good uses** (add value beyond the referenced trait):

| Addition | Example |
|----------|---------|
| Section constraint | `section: rodata` - limit to specific section |
| Count constraint | `count_min: 5` - require multiple occurrences |
| Density constraint | `per_kb_min: 2.0` - require density |
| Criticality change | `crit: suspicious` when base is `notable` |
| Downgrade rules | Add `downgrade:` for context-aware severity |
| Unless conditions | Add `unless:` to skip in certain contexts |

**Bad uses** (pure aliases - will produce validation warnings):

```yaml
# ❌ BAD: Pure alias, no added value
- id: stratum-tcp
  desc: Stratum mining protocol
  crit: notable                      # Same as referenced trait
  if:
    id: objectives/impact/cryptojacking/miner::stratum-tcp
    # No section, count, downgrade, unless, etc.
```

If you need a short name for use in composite rules, reference the original trait directly instead:

```yaml
# ✅ GOOD: Reference directly in composite
composite_rules:
  - id: miner-indicators
    any:
      - id: objectives/impact/cryptojacking/miner::stratum-tcp
      - id: objectives/impact/cryptojacking/miner::stratum-ssl
```

## Exception Directives

| Directive | Purpose |
|-----------|---------|
| `not:` | Filter matched strings (list of `exact`/`substr`/`regex`) |
| `unless:` | Skip if condition matches (trait refs or inline conditions) |
| `downgrade:` | Reduce criticality by one level if condition matches |

**Proximity:** `near_bytes:`, `near_lines:` - require evidence within N bytes/lines

### Downgrade Behavior

Reduces criticality by **one level** when conditions match:

| Original → Downgraded | Use Case |
|----------------------|----------|
| `hostile` → `suspicious` | Known malware signature found in security tool |
| `suspicious` → `notable` | Anti-debug technique in signed system binary |
| `notable` → `baseline` | Common capability in trusted context (becomes invisible) |

**Syntax** (works on both atomic traits and composite rules):

```yaml
traits:
  - id: debugger-check
    desc: Anti-debugging technique
    crit: suspicious                    # Suspicious by default
    conf: 0.85
    if:
      type: symbol
      exact: "ptrace"
    downgrade:                           # → notable if signed
      any:
        - id: metadata/signed/platform::apple
        - id: metadata/quality::versioned

composite_rules:
  - id: process-hollowing
    desc: Process injection technique
    crit: hostile                        # Hostile by default
    conf: 0.95
    all:
      - id: micro-behaviors/process/create
      - id: micro-behaviors/mem/allocate/rwx
    downgrade:                           # → suspicious if debugger
      any:
        - id: micro-behaviors/process/create/load/library::debugger-tool-marker
```

**Note:** Downgrade to `baseline` removes the finding from output entirely. Use `unless:` if you want to skip matching instead.

**Debug:** Use `test-rules` to see downgrade evaluation:
```bash
flayer test-rules file.bin --rules "debugger-check"
# Shows: "Downgrade: suspicious -> notable (triggered)"
```

## KV Path Syntax

For JSON/YAML/TOML manifests (`package.json`, `manifest.json`, `Cargo.toml`, etc.):

```yaml
path: "key"                    # Top-level key
path: "a.b.c"                  # Nested access
path: "arr[0]"                 # Array index
path: "arr[*]"                 # Any array element
path: "scripts.postinstall"    # npm scripts
path: "permissions"            # Chrome extension
```

### Value Matching

Path-only (no matcher) = existence check.

```yaml
# Existence check (field must exist)
type: kv
path: "description"

# Explicit existence check
type: kv
path: "description"
exists: true              # Field must exist

# Non-existence check
type: kv
path: "description"
exists: false             # Field must NOT exist

# String matching
type: kv
path: "scripts.postinstall"
substr: "curl"            # Contains substring

# Exact match
type: kv
path: "license"
exact: "MIT"              # Exact string match

# Regex match
type: kv
path: "version"
regex: "^0\\.0\\.0$"      # Version is 0.0.0
```

### Collection Size Constraints

Constrain collection size (array elements or object keys):

```yaml
# Exactly one maintainer
type: kv
path: "maintainers"
size_min: 1
size_max: 1

# At least 3 dependencies
type: kv
path: "bundledDependencies"
size_min: 3

# No more than 10 keywords
type: kv
path: "keywords"
size_max: 10

# Empty array/object
type: kv
path: "contributors"
size_max: 0
```

**For objects:**

```yaml
# At least 5 dependencies
type: kv
path: "dependencies"
size_min: 5

# No dependencies
type: kv
path: "dependencies"
size_max: 0
```

**Constraint Validation:**
- `size_min`/`size_max` apply to arrays (element count) and objects (key count)
- Scalars (strings, numbers, booleans) will fail size constraints
- Evidence output includes `size: N (array)` or `size: N (object)`

## CLI Reference

```bash
flayer /path/to/file                    # Analyze file
flayer symbols <file>                   # View symbols
flayer strings <file>                   # View strings
flayer test-rules <file> --rules "x,y"  # Debug rules
flayer test-match <file> --type string --pattern "eval"  # Test patterns
```

### test-match Options

| Option | Values |
|--------|--------|
| `--type` | `string`, `symbol`, `raw`, `kv`, `hex`, `encoded`, `base64`, `xor` |
| `--method` | `exact`, `contains`, `regex`, `word` |
| `--pattern` | Search pattern |
| `--encoding` | Encoding filter for `encoded` type: `base64`, `base64,hex`, etc. |
| `--count-min`, `--count-max` | Match count bounds |
| `--per-kb-min`, `--per-kb-max` | Density bounds |
| `--section` | Restrict to section |
| `--offset`, `--offset-range` | Absolute position |
| `--section-offset`, `--section-offset-range` | Section-relative position |
| `--case-insensitive` | Case-insensitive match |
| `--kv-path` | Path for KV searches |
| `--file-type` | Override detection |

## Reference Codes

- **ATT&CK**: `T1234` or `T1234.001`
- **MBC**: `B0001` (behavior), `C0015` (micro-behavior), `E1234` (ATT&CK+MBC)
