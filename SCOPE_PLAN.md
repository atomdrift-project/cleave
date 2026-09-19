# `for:` and `scope:` — one meaning each

Status: engine landed, tree migration pending. Written 2026-09-18.

| step | state |
|---|---|
| `#[package]` marker, both hand lists derived from it | done |
| default scope table (package / archive / outer / file) | done |
| registry pair node typed `registry` | done |
| finding-origin filter (stamp, mask, per-rule intersect) | done |
| `unbindable-package-scope`, `pooling-scope-no-container`, `leg-outside-for` | done |
| traits-dev codemod (1393 legs, 500 containers) | pending |
| corpus before/after | not run |

`make test`: 3254 passed. `cleave validate` on traits-dev: 1393 `leg-outside-for`,
500 `pooling-scope-no-container`, 0 `unbindable-package-scope`.

## The model

**`for:` lists every file type the composite is about.** That is the container it
reports on *and* the member types whose findings may satisfy its legs. It may be
stricter than its children (a subset), never broader in effect.

**`scope:` says how far one evaluation reaches**, and therefore which node the
finding is reported on: the same file, the nearest archive, the nearest package,
or the whole analysis.

Two fields, two questions: *which files am I about* and *how far do I reach*.
Nothing else decides either.

## What changes

Today `for:` gates only the node a composite runs on. Once it runs, **any**
pooled evidence satisfies its legs, whatever member it came from. That is the
`vscode-activated-curl-shell` failure: `for: [vsix]`, `scope: archive`, scored
hostile on the Rust crate `agentdiff-0.1.26` by tying a VS Code marker in one
member to a `curl | sh` README line in another. Removing the archive-family
carve-out fixed *that node* (a crate is not a vsix) but left the general hole:
on a real vsix, any member's findings still count, including members the rule
was never about.

So one addition: **a finding may satisfy a leg only if the file it came from has
a type listed in `for:`.** A rule that ties a vsix manifest to its bundled
script says so:

```yaml
for: [vsix, javascript, json]   # the container + what may be mixed in
scope: archive
```

## Behaviour matrix

### Which node reports

| `scope:` | reports on | pools evidence from |
|---|---|---|
| `leaf` | the analyzed unit itself | that unit, decoded layers separate |
| `file` (default) | the file | that file, decoded layers folded in |
| `archive` | nearest enclosing container | that container's members |
| `package` | nearest enclosing *ecosystem* container | that package's members, skipping generic wrappers |
| `outer` | the analysis root / registry-join node | everything in one `analyze_file` call |

This is already how dispatch works: the per-node pass runs `file`/`leaf`, the
container pass runs `archive`/`package`/`outer`. No dispatch change is needed —
only the finding filter, and the pair node's type (below).

### Default scope, by what `for:` names

| `for:` names | default |
|---|---|
| ecosystem container (npm, gem, whl, nupkg, crate, conda, egg, python_sdist, deb, rpm, alpine_apk, android_apk, xbps, gentoo_binpkg, pkg, msi, ipa, crx, xpi, vsix, oci_image) | `package` |
| generic container (zip, tar, gz, bz2, xz, zst, lzma, archive, iso, asar, static_lib, cab) | `archive` |
| `registry` | `outer` |
| anything else | `file` |

Ecosystem containers win the tie against `archive`: a rule about a package means
the package boundary, not whatever wrapper happens to sit closer.

### `registry` ⇔ `outer`

Registry metadata is fetched *beside* the artifact, so its findings carry no
location and every location-keyed scope collapses to the empty key. The
artifact↔registry join therefore has exactly one spelling:

```yaml
for: [registry, javascript]   # registry facts + what they may be mixed with
scope: outer
```

`evaluate_package_composites` builds its synthetic node as `FileType::All`;
it becomes `FileType::Registry`, so `for:` gates it like any other node.
Registry-side findings are stamped `registry` for the finding filter.

## Rob Pike review

What this plan deliberately does **not** do:

- **No new field.** The question "which files is this rule about" already had a
  field; it just wasn't being enforced. Adding `mixes:` or `members:` beside
  `for:` would give two fields one meaning.
- **No per-evidence file-type plumbing.** The prior design sketch wanted a
  `FileType` threaded onto every `Evidence`. Findings already carry
  `source_file`, and `archive_contents` (path → type) is already threaded into
  the scope filter for `parent_package`. Resolve per *finding*, not per
  evidence item: one lookup, no new data on the hot path.
- **No consumer-relative scoping.** "Nearest relative to me" was considered and
  rejected: `apply_scope_filter` has no notion of where the consuming rule sits,
  and giving it one is an architecture change. Each scope keeps one fixed
  meaning, computed the same way wherever it runs.
- **No degradation to a global pool.** `archive`/`package` with no such ancestor
  behave as `file`. Never wider. Already true; stays true.
- **No carve-outs.** No "self-extracting PE also counts", no "archive-family
  rules may run on any archive". Every one of those was a rule that meant
  something other than what it said.
- **One predicate for package-ness.** `is_registry_fetch_package_type` (for
  defaults) and `is_registry_fetch_package_label` (for ancestor walks) are two
  hand-maintained lists of the same idea — the exact shape of the `ARCHIVES` /
  `is_archive()` drift already found in this tree. Replace both with a
  `#[package]` enum marker, same mechanism as `#[archive]`.

What the review changed:

- Dropped "the composite reports at the scope boundary" as a *change*: it is
  already the behaviour. The plan shrank from a dispatch rewrite to a filter.
- Dropped the proposal to require the union of children's types. `for:` may be
  stricter than its children; the validator only rejects a `for:` that makes a
  required leg unsatisfiable.

## Implementation

1. `#[package]` marker on the ecosystem container variants; derive
   `FileType::is_package()` and the label check from it; delete both
   hand-maintained lists.
2. `default_scope`: ecosystem → `package`, generic archive → `archive`,
   `registry` → `outer`, else `file`.
3. Finding filter: a finding satisfies a leg only if the file it came from has
   a type in the rule's `for:`. `for: [all]` disables the filter.

   Origin is **stamped where nested findings are collected**, not derived later:
   `archive/mod.rs` builds `nested_findings` by walking `report.files`, where
   each member's type is in hand. (The first draft of this plan said to resolve
   it from `Finding.source_file`; that field is populated only by the embedded-
   binary, embedded-code and overlay analyzers, never for ordinary archive
   members, so it would have silently fallen back to the container type for
   every member — the filter would have been a no-op exactly where it matters.)

   Carried as a `TypeMask` (a 256-bit set, one bit per `FileType` variant,
   checked at compile time) per finding id, intersected against a mask
   cached on the composite: no per-rule clone of a finding list that runs to
   millions of entries on a member-heavy archive.
4. Pair node typed `registry`; registry-side findings stamped `registry`.

## Validation

| id | error | fix |
|---|---|---|
| `unbindable-package-scope` | `scope: package` that can never bind (registry-only `for:`; or registry leg mixed with a file leg) | use `scope: outer` |
| `for-excludes-required-leg` | a required leg can only fire on types absent from `for:` — the rule is dead | add the type, or drop the leg |
| `pooling-scope-without-container` | `archive`/`package`/`outer` with no container type in `for:` | name the container the rule reports on |

Each carries the one-line fix in `VALIDATOR_SPECS`, so `--disable-validator`
can name it and the output says what to do.

## Migration

The filter makes every archive-scoped composite that lists only its container
dead — it reports on the npm node while its legs fire on javascript members.
That is most of the 2287 archive-scoped composites in the tree, so the migration
is a codemod, not hand edits: for each composite, union the `for:` of its
required legs into its own `for:`, then let `for-excludes-required-leg` prove
the tree is clean. Authors tighten from there; the validator never asks for
more than the legs need.

Corpus risk: adding member types back is mechanical, but it cannot prove the
rule still *means* the same thing. The benign corpus and the mislabeled-good
triage sets must be re-scanned before and after, and the finding delta reviewed
rule-family by rule-family. Nothing here should change a verdict; any that does
is a rule that was relying on evidence it never declared.

## Open

- Every path that feeds findings into a container evaluation must stamp the
  origin type, not just `archive/mod.rs`: `office/mod.rs` and `pdf.rs` build
  their own `nested_findings` from `report.findings[..]` slices, where the
  member type is less directly at hand. An unstamped finding must default to
  *excluded-unless-`all`*, not to the container type, so a missed call site
  shows up as a rule that stops firing rather than one that fires on anything.
- `jar` is deliberately on the generic side: it is a container format reused
  everywhere (jar-in-war, jar-in-ear), not a boundary an author means when they
  write "this package". `dmg` likewise sits with `iso`.
- `crx`/`xpi`/`vsix` are on the ecosystem side by the one-line rule ("a unit of
  distribution"). Their members are direct, so it changes nothing today.
