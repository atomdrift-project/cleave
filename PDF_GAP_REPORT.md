# PDF Detection Gap Report

Cross-reference of Didier Stevens' `pdf-parser.py` (v0.7.14) against
cleave's lenient PDF extractor (`src/analyzers/pdf/`) and the existing
trait surface in `cleave-traits/metadata/document/pdf/`. Spot-checked
against samples in `/Users/t/data/STAGING/pdf` (802 PDFs).

## Biggest gap: `/ObjStm` is invisible to cleave

The lenient parser walks top-level indirect objects only, so it sees
~10 objects in modern PDFs while pdf-parser-with-ObjStm-decompression
sees 30–40+. Every embedded file, JS action, and AcroForm dict in the
2020+ samples in the staging set lives inside a FlateDecoded `/ObjStm`
stream.

Concrete miss — `05d8bc12d167cf6d1f56bfa8060b10f92c5688f960a2a34e2983be4739e60808.pdf`:

- cleave value reports no `embedded_files[]`
- pdf-parser sees `/EmbeddedFile` at obj 22 inside the ObjStm

Same shape for `09c42b8d83803d156de74d61fe14cc06072599442a6da4212e8a588c3df9a7ad.pdf`
(JS action source = `named:JavaScript` with empty snippet because the
resolver can't follow into the ObjStm).

**Suggestion:** after first pass, if `/ObjStm` filter is present and
`embedded_file_count == 0` / `actions[].snippet.is_empty()`, inflate
ObjStm streams and re-run the dict scan over the decompressed body.
Augments existing collectors; no `PdfDocument` API change.

## value fields to add (cheap; the parser already has the data)

Counts pdf-parser surfaces from `dicObjectTypes` that are direct anomaly
signal — add to `shape.*`:

- **`shape.annotation_count`** — phishing PDFs in this set: 1–2 pages
  with **22–28 `/Annot` all carrying `/URI`** (e.g. `00000416…`,
  `0001e5a7…`). Today cleave shows 22 `actions[].kind=uri` but no
  annotation-per-page ratio. A composite
  `pdf-link-bait-density = uri_action_count / page_count >= 5`
  would catch this whole cluster.
- **`shape.page_count`**, **`shape.xobject_count`**,
  **`shape.font_count`**, **`shape.metadata_count`**
- **`shape.objstm_count`** — non-zero on every modern sample;
  presence + low surfaced action count = "cleave can't see inside,
  treat with suspicion".
- **`shape.xref_stream_count`** (i.e. `/XRef` objects) — when nonzero,
  the file has NO classical `xref`/`trailer`; useful disambiguator.
- **`shape.unreferenced_object_count`** — Stevens calls this out
  explicitly; orphaned objects are a known hiding place. Easy to
  compute from `objectsAll - objectsReferenced` using the references
  the parser already scans.
- **`shape.trailing_bytes_after_eof`** — bytes between last `%%EOF`
  and file end. Non-zero is a strong appended-payload signal not
  currently surfaced.
- **`shape.streams_with_unusual_filter_count`** — count of
  `JBIG2Decode | LZWDecode | Crypt` (already partially have JBIG2;
  LZW + Crypt are missing).

## Action / catalog gaps

- **`catalog.has_names_javascript`** — `/Names /JavaScript << /Names
  [ … ] >>` named-action tree. Currently we set
  `actions[].source = "named:JavaScript"` but lose the flag at the
  catalog level, so a kv rule has to scan `actions[*].source`.
- **`catalog.has_richmedia`**, **`catalog.has_3d`** — already track
  `three_d_object_count` but `/RichMedia` annotations
  (CVE-2009-1862 family / Flash-in-PDF) aren't separated.
- **`actions[].snippet`** is empty when the JS body lives in an
  ObjStm or in an indirect object the resolver doesn't chase. Fixing
  the ObjStm gap fixes this too.

## /Info decoding (visible bug)

`info.author = "�� k a l a r o n e"` on `00000416…` — that's a
UTF-16BE string (`FE FF` BOM, big-endian 16-bit). The collector is
taking raw bytes. Decoding UTF-16BE when BOM is present would make
`info.*` actually usable for the Cyrillic/CJK regex traits in
`metadata/document/pdf/properties/traits.yaml` (which today wouldn't
match `0x00 D 0x00 i 0x00 m …` no matter how good the regex is).

## Stats-style atomics worth adding under `metadata/document/pdf/structure/traits.yaml`

Composites the new value fields unlock — each is a one-line `type: value`
regex:

- **`pdf-link-spam-density`** —
  `shape.annotation_count >= 10 AND shape.page_count <= 2`
  (or compute ratio in a future metric).
- **`pdf-uri-only-no-text`** — `actions[*].kind=uri` count vs
  `shape.font_count == 0` → image-only PDF that's just a clickable
  link (this set has dozens).
- **`pdf-objstm-with-low-visible-objects`** —
  `shape.objstm_count >= 1 AND shape.object_count < 15`.
- **`pdf-unreferenced-objects`** —
  `shape.unreferenced_object_count > 0` (suspicious-tier; benign
  PDFs with linearization may also trip, so worth measuring FP rate
  first).
- **`pdf-appended-payload`** —
  `shape.trailing_bytes_after_eof > 1024` (1 KiB threshold avoids
  whitespace noise).
- **`pdf-xref-stream-only`** —
  `shape.xref_stream_count >= 1 AND header.header_count == 1` — not
  malicious alone, but a useful clustering bucket distinct from
  classical PDFs.

## Trait-only (no parser change) wins available today

These don't need new value fields, just YAML in
`metadata/document/pdf/`:

- `actions[*].source` regex `^object:` paired with
  `actions[*].kind=javascript` → JS attached via indirect object
  rather than catalog (less common in benign docs).
- `filter_chains[*]` regex `LZWDecode|Crypt|RunLengthDecode` —
  niche filters; LZW is mostly seen on legacy or evasive PDFs.
- `filter_chains[*]` containing same filter twice
  (`FlateDecode,FlateDecode`) — over-encoding for evasion.
- `info.producer` regex matching `iText|TCPDF|FPDF` (programmatic
  generators) — useful clustering against scanner / Word output.

## Recommended priorities

1. **ObjStm decompression + re-scan** — single biggest detection
   lift; without it ~half the staging set is under-analyzed.
2. **UTF-16BE info decoding** — silently breaks existing properties
   traits.
3. **Add `shape.{annotation_count, page_count, objstm_count,
   unreferenced_object_count, trailing_bytes_after_eof}`** — enables
   the link-spam phishing cluster which dominates this sample set.
4. The composite YAML traits above.

## Reference: what `pdf-parser -a` surfaces that cleave does not

Per-object-type counts (`dicObjectTypes`), keyword counts
(`/JS /JavaScript /AA /OpenAction /AcroForm /RichMedia /Launch
/EmbeddedFile /XFA /URI`), unreferenced indirect objects, comment
count, indirect-objects-with-stream list, XRef/Trailer/StartXref
counts, and `/ObjStm` inner-object parsing.
