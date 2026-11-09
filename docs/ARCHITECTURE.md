# Architecture

cleave is one of five projects. Each answers one question, and the
dependencies run one way: nothing below knows about anything above it.

```
traits     which of it matters?                         policy (YAML)
cleave     what's inside, and what does it mean?        iterate, recurse, budget, judge
unpack     what bytes does this file hide?              transform bytes → derived bytes
filefacts  what is this file, and what does it say?     identify, parse, locate
stng       which strings are in these bytes?            string recovery
```

| Project | Owns | Never does |
| --- | --- | --- |
| [stng](https://github.com/atomdrift-project/stng) | Strings in a buffer: byte scans, Go/Rust `{ptr,len}` strings, stack strings, string-level decoding (base64, hex, escapes, XOR) | Know file formats beyond string layout |
| [filefacts](https://github.com/atomdrift-project/filefacts) | File identification; every format parser; facts, metrics, symbols, sections, archive member lists, identity and trust; locating what a file carries (packer, installer, embedded image, bundle, overlay) | Produce new files; hold lists of known packages, hosts or brands; assign severity |
| [unpack](https://github.com/atomdrift-project/unpack) | Turning bytes into the bytes they hide: executable unpackers (UPX, MPRESS, NRV), payload decryptors, installer payloads (Nuitka, PyInstaller), script and stub deobfuscators | Decide what to unpack; emit findings or severity; walk archives |
| cleave | Archive extraction and iteration; recursion, depth and byte budgets; scheduling; running each recovered file back through filefacts; trait evaluation; the report | Parse a file format; measure a file property filefacts could |
| [traits](https://github.com/atomdrift-project/traits) | Every judgement: severity, thresholds, benign exceptions, anything naming a package, host or vendor | — |

## Where does new code go?

Ask in order:

1. **Is the output strings?** → stng.
2. **Is it a measurement of one file's own bytes?** (a header field, a count,
   a parse result, where a payload sits) → filefacts, as a fact. No
   judgement, no names of known packages or hosts.
3. **Is the output a new file to analyze?** → unpack (or, for an archive
   member, cleave's archive iteration).
4. **Does it need several files, a budget, an external fetch, or the
   outcome of extraction?** → cleave. Record outcomes as facts
   (`archive_guard.*`, `archive.guard.*`, `strings.*`) for traits to judge.
5. **Is it a decision about meaning?** → a trait. If the decision needs a
   reviewed list, ship it as a named dataset (`src/datasets/*.yaml`) behind
   a generic validator (`is: sus_hostname`, `is: {typo_of: <dataset>}`).

## Rules that follow

- **One parse per file.** cleave opens one filefacts context per file and
  reads every fact from it; it never re-walks a header filefacts already
  read. Where cleave needs a format answer mid-pipeline, filefacts exports a
  function (`archive_magic`, `chm::directory`, `size_probe`,
  `has_embedded_executable`).
- **Facts are neutral.** filefacts says what a file states; whether that is
  suspicious is a trait. A fact that is only meaningful with a list of
  names belongs in a trait or dataset, not in a parser.
- **Transforms don't judge.** unpack returns derived bytes with provenance
  (method, source range, limits hit) or a refusal. A refusal is an outcome
  cleave records as a fact; traits decide whether it matters.
- **Policy is tunable without an engine release.** Severity and exceptions
  live in traits; changing them never needs a cleave build. New trait
  *syntax* does: release cleave before shipping traits that use it.
- **External tools are the caller's.** Anything that runs a subprocess (7z,
  innoextract) is invoked through a runner the caller supplies, so timeouts,
  sandboxing and the no-external-commands policy stay in one place.

## Status

Parsing is in filefacts; unpackers, payload decryptors, installer payloads
(Nuitka, PyInstaller) and script reconstructors are in unpack. cleave calls
them and attaches what they recover:

- `upx.rs` runs the `upx` tool (an external tool, so the caller's) and
  applies the triage policy; what a refusal means, checksum repair and
  packed-image recognition are `unpack::upx`.
- `extractors/encoded_payload.rs` turns strings stng already decoded, and
  keys filefacts already found, into analyzable payloads. It parses no
  format.
- The script reconstructors walk the syntax tree filefacts built, so each
  file is still parsed once.

Still policy in code, pending traits: the UPX `standard-unpack-refused`
finding, and the Firefox-profile and test-source exceptions in
`analyzers/embedded_code_detector`.

`analyzers/signature.rs` maps filefacts' trust facts to per-signer finding
ids (`metadata/signature/<state>/<kind>::<name>`). It reads facts and parses
nothing; it stays in cleave as the engine's identity index.
