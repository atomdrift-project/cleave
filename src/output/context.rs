//! Context window rendering: ASCII, text, hex and source lines.

// Split out of the parent module for size; it shares the parent's namespace.
#[allow(clippy::wildcard_imports)]
use super::*;

/// Emit the merged context. Source files render line-by-line; binaries render
/// each match window as raw bytes wrapped into hex|ascii rows at `term_width`.
pub(super) fn render_context(
    out: &mut String,
    file: &FileAnalysis,
    selected: &[&str],
    plan: &[Planned<'_>],
    owed: &HashSet<&str>,
    opts: &TinyOpts,
    term_width: usize,
    colorize: bool,
) {
    if is_binary_file_type(&file.file_type) {
        // The machine/LLM view (Minimal header) renders binary windows as
        // ASCII-forward rows with an xxd-style offset gutter — no hex column —
        // which a local model reads far more cheaply than a hex|ascii dump.
        // The terminal view keeps the hex|ascii rows.
        if matches!(opts.header, HeaderStyle::Minimal) {
            render_ascii_context(out, file, plan, opts);
        } else {
            render_hex_context(out, file, plan, selected, term_width, opts, colorize);
        }
    } else {
        render_text_chunks(out, file, plan, owed, opts, term_width, colorize);
    }
}

/// Render binary context for the machine/LLM view: each run of matched bytes as
/// ASCII-forward rows — printable bytes verbatim, non-printables as C-string
/// escapes — preceded by one `{marker} SEV OFFSET desc` line per detection in
/// that run, so the detections describe the bytes that follow. Every row opens
/// with an xxd-style gutter (the absolute byte offset of its first byte in
/// unpadded hex), `:` when a detection matched inside the row and `-` when it is
/// surrounding context, so any byte is addressable without the terminal view's
/// hex column and a clipped run needs no `…` marker.
///
/// A captured window is split into one block per contiguous run its own
/// annotations cover. Capture merges overlapping windows, and low-tier traits
/// this view does not list bridge them: on `/bin/ls` sixteen listed detections
/// arrived as a single 1.5 KB window, so the block stopped describing the bytes
/// it held. Splitting on the gaps restores the property that makes the view
/// readable — every block is contiguous data that its own annotations account
/// for.
pub(super) fn render_ascii_context(
    out: &mut String,
    file: &FileAnalysis,
    plan: &[Planned<'_>],
    opts: &TinyOpts,
) {
    use std::fmt::Write;
    let marker = comment_marker(&file.file_type);
    let mut emitted = false;
    for (line, w) in file.context.iter().zip(plan) {
        let Some(ids) = &w.ids else {
            continue;
        };
        // Distinct planned findings on this window. (Placement already capped
        // locations per trait; merging can pool several here.)
        let mut seen = HashSet::new();
        let notes: Vec<&Note> = w
            .notes
            .iter()
            .filter(|n| ids.contains(n.id.as_str()) && seen.insert(n.id.as_str()))
            .collect();
        if notes.is_empty() {
            continue;
        }

        let blocks = ascii_blocks(line, notes, opts.lean_rows);

        for (start, end, mut block_notes) in blocks {
            // A blank line sets each block apart — from the file-level
            // annotations above the first one, and from the preceding block.
            if emitted || (!out.is_empty() && !out.ends_with("\n\n")) {
                out.push('\n');
            }
            emitted = true;

            // Strongest first: the block leads with the worst thing in it.
            block_notes.sort_by(|a, b| b.crit.cmp(&a.crit).then_with(|| a.off.cmp(&b.off)));
            // Each annotation carries the hex offset of the bytes it fired on,
            // in the same base and form as the row gutter below, so a detection
            // can be pointed at its bytes even when a block holds several. The
            // text view has always shown `LINE:COL` here.
            for note in &block_notes {
                let _ = writeln!(
                    out,
                    "{marker} {} {:x} {}",
                    note.crit.letter(),
                    note.off,
                    annotate_desc(&terse_description(&note.desc), &note.id)
                );
            }

            let mut row = start;
            while row < end {
                let row_end = (row + ASCII_ROW).min(end);
                let row_lo = line.loc + row as u64;
                let row_hi = line.loc + row_end as u64;
                // `:` marks a row a detection actually matched in, `-` a row of
                // surrounding context — the same distinction the terminal
                // view's gutter draws.
                let hit = block_notes
                    .iter()
                    .any(|n| n.off < row_hi && n.off + u64::from(n.len.max(1)) > row_lo);
                let _ = writeln!(
                    out,
                    "{row_lo:x}{} {}",
                    if hit { ':' } else { '-' },
                    ascii_printable(&line.data[row..row_end])
                );
                row = row_end;
            }
        }
    }
}

/// Split a binary window into contiguous blocks around its selected notes.
pub(super) fn ascii_blocks<'a>(
    line: &'a ContextLine,
    mut notes: Vec<&'a Note>,
    lean: bool,
) -> Vec<(usize, usize, Vec<&'a Note>)> {
    let len = line.data.len();
    let within = |off: u64| {
        usize::try_from(off.saturating_sub(line.loc))
            .unwrap_or(usize::MAX)
            .min(len)
    };
    notes.sort_by_key(|n| n.off);
    let mut blocks: Vec<(usize, usize, Vec<&Note>)> = Vec::new();
    for note in notes {
        let (before, after) = if lean {
            (0, ASCII_ROW as u64)
        } else {
            note.crit.hex_context()
        };
        let lo = within(note.off).saturating_sub(before as usize);
        let hi = within(note.off.saturating_add(u64::from(note.len.max(1))))
            .saturating_add(after as usize)
            .min(len);
        match blocks.last_mut() {
            Some((_, end, group)) if lo <= *end => {
                *end = (*end).max(hi);
                group.push(note);
            }
            _ => blocks.push((lo, hi, vec![note])),
        }
    }
    blocks
}

/// Bytes per gutter-prefixed row in the ASCII-forward view. Wider than xxd's 16
/// so the escaped stream stays token-cheap for a model, while every row still
/// carries an addressable offset.
pub(super) const ASCII_ROW: usize = 64;

/// Minimum `<printable>\0` pairs to treat a run as UTF-16LE ASCII and collapse
/// it to text. PE version-info / Authenticode strings are UTF-16LE and sit at
/// mid-file offsets (no BOM for [`crate::file_io::normalize_text_encoding`] to
/// catch), so without this `ProductName` renders as `P<00>r<00>o<00>…`.
pub(super) const UTF16_RUN: usize = 4;

/// The printable projection of a byte window: printable ASCII verbatim, a
/// UTF-16LE ASCII run collapsed to its text, and every other byte — NUL,
/// control, high-bit, machine code — a single space, runs of them one space.
///
/// What the model reads in a window is the strings: a path, a method name, a
/// key, an import. Machine-code bytes between them are not evidence it can
/// use, but rendered as `\xNN` escapes they cost three to four tokens each,
/// and a 54 MB ELF's 107 windows came to 40k tokens. Measured on
/// 32 benchmark renders graded by a model, five runs each: this
/// projection cut the prompts 21% overall (a binary-heavy render 41.5k →
/// 27.6k tokens) with every grade unchanged, where dropping the context rows
/// or collapsing runs to a `.{n}` marker each flipped a known-bad .NET
/// sample. The string boundaries stay visible (each non-printable run is a
/// space), which is what kept `get_Threshold set_Threshold …` readable as
/// separate names.
pub(super) fn ascii_printable(data: &[u8]) -> String {
    let printable = |b: u8| (0x20..=0x7e).contains(&b);
    let mut s = String::with_capacity(data.len());
    let mut i = 0;
    let mut gap = false;
    while i < data.len() {
        let mut run = 0;
        while i + run * 2 + 1 < data.len()
            && printable(data[i + run * 2])
            && data[i + run * 2 + 1] == 0
        {
            run += 1;
        }
        if run >= UTF16_RUN {
            if gap {
                s.push(' ');
                gap = false;
            }
            for k in 0..run {
                s.push(data[i + k * 2] as char);
            }
            i += run * 2;
            continue;
        }
        let b = data[i];
        if printable(b) {
            if gap {
                s.push(' ');
                gap = false;
            }
            s.push(b as char);
        } else {
            gap = true;
        }
        i += 1;
    }
    if gap {
        s.push(' ');
    }
    s
}

/// A physical line within a textual chunk: its absolute byte range in the file
/// and the 1-based source position of its first content byte. Splitting a
/// byte-addressed chunk into these rows is what lets one renderer serve both a
/// normal multi-line window (numbered lines) and a slice of an ultra-long line
/// (a single pseudo-line labelled `line:col`).
pub(super) struct ChunkRow {
    /// Absolute byte offset of the row's first content byte.
    pub(super) off: u64,
    /// 1-based source line.
    pub(super) line: u64,
    /// 1-based column of the first content byte (>1 for a mid-line slice).
    pub(super) col: u64,
    /// Byte range `[start, end)` of the row's content in `chunk.data`, excluding
    /// any trailing `\r`/`\n`.
    pub(super) start: usize,
    pub(super) end: usize,
    /// Absolute offset where the next row begins — the exclusive upper bound for
    /// assigning a note to this row.
    pub(super) cover_end: u64,
}

/// Split a textual chunk into physical rows. The first row starts at the chunk's
/// own `line`/`col` (which may be mid-line, when the chunk slices an ultra-long
/// line); each subsequent row begins at column 1 on the next line.
pub(super) fn chunk_rows(chunk: &ContextLine) -> Vec<ChunkRow> {
    let base = chunk.loc;
    let mut line = chunk.line.unwrap_or(0);
    let mut col = chunk.col.unwrap_or(1);
    let data = &chunk.data;
    let mut rows = Vec::new();
    let mut start = 0usize;
    for i in 0..data.len() {
        if data[i] == b'\n' {
            // Drop a CRLF's `\r` so the row doesn't render a trailing carriage return.
            let end = if i > start && data[i - 1] == b'\r' {
                i - 1
            } else {
                i
            };
            rows.push(ChunkRow {
                off: base + start as u64,
                line,
                col,
                start,
                end,
                cover_end: base + i as u64 + 1,
            });
            start = i + 1;
            line += 1;
            col = 1;
        }
    }
    rows.push(ChunkRow {
        off: base + start as u64,
        line,
        col,
        start,
        end: data.len(),
        cover_end: base + data.len() as u64,
    });
    rows
}

/// Render textual context: every stored chunk is an already-sized byte window.
/// Each chunk is split into physical rows and rendered `grep -n`-style — numbered
/// lines with a `# SEV desc` trailer on hits (colored) or a `{marker} SEV
/// line:col desc` annotation before each hit (LLM). A chunk that is a slice of an
/// ultra-long line has a single row, rendered as one `line:col` pseudo-line
/// clipped to the content width with `…` marking the trimmed sides.
pub(super) fn render_text_chunks(
    out: &mut String,
    file: &FileAnalysis,
    plan: &[Planned<'_>],
    owed: &HashSet<&str>,
    opts: &TinyOpts,
    term_width: usize,
    colorize: bool,
) {
    let minimal = matches!(opts.header, HeaderStyle::Minimal);
    let marker = comment_marker(&file.file_type);

    // Chunks the plan draws, each with the finding ids it annotates.
    let shown: Vec<(&ContextLine, &[Note], &HashSet<&str>)> = file
        .context
        .iter()
        .zip(plan)
        .filter_map(|(c, w)| w.ids.as_ref().map(|ids| (c, w.notes, ids)))
        .collect();
    if shown.is_empty() {
        return;
    }

    // Gutter width spans the widest line number across shown chunks.
    let loc_width = shown
        .iter()
        .map(|(c, _, _)| {
            let last = c.line.unwrap_or(0) + c.data.iter().filter(|b| **b == b'\n').count() as u64;
            last.max(1).to_string().len()
        })
        .max()
        .unwrap_or(1);

    // Fixed content column so comments align; long lines truncate to it. The
    // machine/LLM view has no terminal to fit and carries its description on a
    // preceding annotation line, so it shows a generous window of the code —
    // minified code carries its signal far past column 35. The card layout's
    // 3-space lead is two columns wider than the severity gutter.
    let prefix = if opts.card {
        CARD_ROW_LEAD.len() + loc_width + 2
    } else {
        src_prefix(loc_width)
    };
    let content_width = if minimal {
        SRC_LLM_WIDTH
    } else {
        term_width
            .saturating_sub(prefix + 2 + SRC_COMMENT_BUDGET)
            .clamp(24, 100)
    };
    let layout = SourceLayout {
        owed,
        marker,
        loc_width,
        content_width,
        term_width,
        colorize,
        card: opts.card,
    };

    // Set the context off from any file-level annotations above it (LLM view).
    if minimal && !out.is_empty() && !out.ends_with("\n\n") {
        out.push('\n');
    }

    let mut emitted = false;
    for (chunk, chunk_notes, ids) in shown {
        // A blank line sets each window apart as its own paragraph — except in
        // the card layout, where the line-number gaps already mark the jumps
        // and the block stays one compact unit.
        if emitted && !opts.card && !out.ends_with("\n\n") {
            out.push('\n');
        }
        emitted = true;

        // The window ends mid-line (its last row is a clipped tail) when the chunk
        // stops before a newline and more file follows — then that row earns a
        // trailing `…`.
        let chunk_end = chunk.loc + chunk.data.len() as u64;
        let cut_right = chunk.data.last() != Some(&b'\n') && chunk_end < file.size;
        let rows = chunk_rows(chunk);
        let last = rows.len().saturating_sub(1);
        // In focused mode a hit at or above `focus_crit` keeps one following
        // line of real code — but only when the hit fit on a single line
        // (`hit_rows` counts consecutive hit lines; a two-line hit has shown
        // its continuation already). Every other note-less row is dropped;
        // near-empty rows — a lone `}`, a blank — don't satisfy the trail.
        let mut hit_rows = 0usize;
        // Index of the last row actually rendered, so a jump over dropped rows
        // can be marked. A chunk is one contiguous byte range, but the loop
        // below renders only rows that carry a match or real surrounding code —
        // so consecutive output lines are routinely not consecutive source
        // lines. Run together they read as one block of code that never existed.
        let mut last_rendered: Option<usize> = None;
        // Rows accumulate here so a finished block can be trimmed before it is
        // appended — a block's first or last line carrying nothing visible is
        // padding, and against a blank separator it reads as a gap twice as big
        // as the one that is really there.
        let mut block = String::new();
        for (idx, row) in rows.iter().enumerate() {
            let bytes = &chunk.data[row.start..row.end];
            // Notes whose match starts within this row's byte span.
            let notes: Vec<&Note> = chunk_notes
                .iter()
                .filter(|n| {
                    ids.contains(n.id.as_str()) && n.off >= row.off && n.off < row.cover_end
                })
                .collect();
            // A context row (no match of its own) earns a line only when it carries
            // real code — skip near-empty ones like a lone `}` that add height
            // without context. A hit row always renders.
            let real_code = bytes.iter().filter(|b| !b.is_ascii_whitespace()).count() >= 6;
            if notes.is_empty() {
                if opts.focus_crit.is_some() {
                    if !(hit_rows == 1 && real_code) {
                        continue;
                    }
                    hit_rows = 0;
                } else if !real_code {
                    continue;
                }
            } else if opts
                .focus_crit
                .is_some_and(|fc| notes.iter().any(|n| n.crit >= fc))
            {
                hit_rows += 1;
            } else {
                hit_rows = 0;
            }
            // A blank line where rows were dropped: each run of consecutive
            // source lines becomes its own block. The card layout prints a line
            // number on every row, so its jumps are already legible and it stays
            // one compact unit.
            if !opts.card && last_rendered.is_some_and(|prev| prev + 1 != idx) {
                push_source_block(out, &mut block);
            }
            last_rendered = Some(idx);

            let comment = notes
                .iter()
                .copied()
                .max_by_key(|n| (n.crit, std::cmp::Reverse(n.off)));
            render_source_line(
                &mut block,
                &SourceRow {
                    data: bytes,
                    byte_base: row.off,
                    line_no: row.line,
                    col_base: row.col,
                    cut_right: idx == last && cut_right,
                    notes: &notes,
                    comment,
                },
                &layout,
            );
        }
        push_source_block(out, &mut block);
    }
}

/// Append one block of rendered source rows, set off by a blank line, with any
/// leading or trailing rows that carry no visible text dropped.
///
/// A match can land on an empty source line, and a block that opens or closes on
/// one reads — next to the blank line separating blocks — as a gap twice the
/// size of the real one. Trimming is by rendered text, so a terminal row that is
/// blank apart from its line-number gutter is content and stays. A block that is
/// nothing but blank rows appends nothing, so it can never leave a stray
/// separator behind.
pub(super) fn push_source_block(out: &mut String, block: &mut String) {
    let mut lines: Vec<&str> = block.lines().collect();
    while lines.first().is_some_and(|l| l.trim().is_empty()) {
        lines.remove(0);
    }
    while lines.last().is_some_and(|l| l.trim().is_empty()) {
        lines.pop();
    }
    if !lines.is_empty() {
        if !out.is_empty() && !out.ends_with("\n\n") {
            if !out.ends_with('\n') {
                out.push('\n');
            }
            out.push('\n');
        }
        out.push_str(&lines.join("\n"));
        out.push('\n');
    }
    block.clear();
}

/// Render binary context: each shown window is a raw-byte unit, wrapped into
/// hex|ascii rows whose width tracks the terminal, with a `// SEV desc` trailer
/// aligned in a hex-editor gutter.
pub(super) fn render_hex_context(
    out: &mut String,
    file: &FileAnalysis,
    plan: &[Planned<'_>],
    selected: &[&str],
    term_width: usize,
    opts: &TinyOpts,
    colorize: bool,
) {
    let sel: HashSet<&str> = selected.iter().copied().collect();
    // Every window holding a selected match (capture already capped the
    // locations per trait — atomic up to 3, composite 1).
    let show: Vec<usize> = plan
        .iter()
        .enumerate()
        .filter(|(_, w)| w.notes.iter().any(|n| sel.contains(n.id.as_str())))
        .map(|(i, _)| i)
        .collect();
    if show.is_empty() {
        return;
    }

    // Offset column width spans the last byte of every shown window.
    let loc_width = show
        .iter()
        .map(|&i| {
            let l = &file.context[i];
            format!("{:x}", l.loc + l.data.len() as u64).len()
        })
        .max()
        .unwrap_or(1);
    let stride = hex_stride(term_width, loc_width);
    let marker = comment_marker(&file.file_type);

    let layout = HexLayout {
        sel: &sel,
        stride,
        marker,
        loc_width,
        term_width,
        opts,
        colorize,
    };
    for &i in &show {
        render_hex_unit(out, &file.context[i], plan[i].notes, &layout);
    }
}

/// True for file types whose context renders as a hex+ascii dump.
/// Mirrors `filefacts::FileType::is_binary()` without requiring the enum.
pub(crate) fn is_binary_file_type(file_type: &str) -> bool {
    matches!(
        file_type,
        "elf"
            | "pe"
            | "macho"
            | "java_class"
            | "python_bytecode"
            | "beam"
            | "wasm"
            | "dos_com"
            | "shellcode"
    )
}

/// Line-comment marker for the sample's language; `//` for binary and anything
/// C-family, so the annotation reads like a comment the analyst wrote.
pub(super) fn comment_marker(file_type: &str) -> &'static str {
    match file_type {
        "python" | "shell" | "bash" | "ruby" | "perl" | "r" | "powershell" | "yaml" | "toml"
        | "makefile" | "dockerfile" | "systemd_service" | "desktop_entry" | "text" | "ini"
        | "properties" => "#",
        "lua" | "sql" | "haskell" | "applescript" | "vbs" | "vba" => "--",
        _ => "//",
    }
}

/// Comment text reserved at the end of a hex row when sizing the row width, so a
/// meaningful `// desc` trailer fits before any truncation kicks in.
pub(super) const HEX_COMMENT_BUDGET: usize = 44;
/// Hex rows drawn either side of a match in the full-context views. One row of
/// neighbouring bytes is what places a match in its surroundings; beyond that
/// the block stops being evidence and starts being a hex editor.
pub(super) const HEX_MARGIN_ROWS: usize = 1;
/// As [`HEX_MARGIN_ROWS`], for a hostile match — the one case where what runs
/// alongside the bytes carries the verdict.
pub(super) const HEX_MARGIN_HOSTILE: usize = 2;
/// Comment width reserved on source lines — enough that typical descriptions
/// land in full; the code column takes the rest.
pub(super) const SRC_COMMENT_BUDGET: usize = 56;
/// Source content window for the machine/LLM (Minimal-header) view, where there
/// is no terminal width to fit. Wide enough that a minified line's match keeps
/// real surrounding context, while still bounding token cost per line.
pub(super) const SRC_LLM_WIDTH: usize = 512;
/// Fixed columns ahead of a row's hex cells: the 1-char gutter, a space, the
/// offset, and a two-space separator.
pub(super) const fn row_prefix(loc_width: usize) -> usize {
    1 + 1 + loc_width + 2
}

/// Row lead in the card layout: a single space, so the *left-justified*
/// location column starts directly under the `📄` glyph — every row's first
/// digit lands in the same column instead of drifting with the offset width.
pub(super) const CARD_ROW_LEAD: &str = " ";
/// Fixed columns ahead of a source line's code: the 1-char gutter abuts the
/// offset (no space — they read as one unit), then a two-space separator.
pub(super) const fn src_prefix(loc_width: usize) -> usize {
    1 + loc_width + 2
}

/// Bytes per hex|ascii row, chosen so a full row plus its comment fits the
/// terminal: each byte costs 4 columns (`"XX "` + one ascii char), and the
/// prefix, a two-space pad, and the comment budget are reserved. Capped at a
/// hex-editor-like 16 so wide terminals leave ample room for the annotation.
pub(super) fn hex_stride(term_width: usize, loc_width: usize) -> usize {
    let fixed = row_prefix(loc_width) + 2 + HEX_COMMENT_BUDGET;
    let avail = term_width.saturating_sub(fixed);
    (avail / 4).clamp(8, 16)
}

/// One-character severity gutter: `H`/`S` for hostile/suspicious, a `·` for
/// notable and below, a space when the row carries no match. Tinted by severity.
pub(super) fn gutter_glyph(crit: Option<Criticality>, colorize: bool) -> String {
    let Some(crit) = crit else {
        return " ".to_string();
    };
    let ch = match crit {
        Criticality::Hostile => "H",
        Criticality::Suspicious => "S",
        _ => "·",
    };
    if colorize {
        let (r, g, b) = crit_rgb(crit);
        ch.truecolor(r, g, b).to_string()
    } else {
        ch.to_string()
    }
}

/// Pick the byte window `[b0, b1)` of `text` to show within `content_width`
/// display columns, keeping the primary match visible: end-clip (drop the tail,
/// trailing `…`) when the match starts within the width, else begin-clip with a
/// leading `…` so at least 16 chars precede the match. Returns the window plus
/// whether each end is elided. Assumes `text` exceeds `content_width`.
pub(super) fn source_window(
    text: &str,
    content_width: usize,
    match_byte: Option<usize>,
) -> (usize, usize, bool, bool) {
    let chars: Vec<(usize, char)> = text.char_indices().collect();
    let n = chars.len();
    if n <= content_width {
        return (0, text.len(), false, false);
    }
    let byte_at = |ci: usize| chars.get(ci).map_or(text.len(), |&(bi, _)| bi);
    // The primary match's char index (first char at or after its byte offset).
    let mc = match_byte
        .and_then(|mb| chars.iter().position(|&(bi, _)| bi >= mb))
        .unwrap_or(0);

    // End-clip keeps the match when it starts within the width (1 col for `…`).
    if mc < content_width.saturating_sub(1) {
        return (0, byte_at(content_width - 1), false, true);
    }
    // Begin-clip: show ≥16 chars of lead before the match.
    let w0 = mc.saturating_sub(16);
    let lead = w0 > 0;
    let mut w1 = (w0 + content_width.saturating_sub(usize::from(lead) + 1)).min(n);
    let trail = w1 < n;
    if !trail {
        w1 = (w0 + content_width.saturating_sub(usize::from(lead))).min(n);
    }
    (byte_at(w0), byte_at(w1), lead, trail)
}

/// One source row to render: its bytes, where they sit in the file, and the
/// notes whose match starts on it.
#[derive(Clone, Copy)]
pub(super) struct SourceRow<'a> {
    pub(super) data: &'a [u8],
    /// Absolute offset of the row's first byte.
    pub(super) byte_base: u64,
    /// 1-based source line of the row's first byte.
    pub(super) line_no: u64,
    /// 1-based source column of the row's first byte.
    pub(super) col_base: u64,
    /// The source line continues past the captured window.
    pub(super) cut_right: bool,
    pub(super) notes: &'a [&'a Note],
    /// The note the row's trailing comment describes.
    pub(super) comment: Option<&'a Note>,
}

/// How every row of one file's source context is laid out.
#[derive(Clone, Copy)]
pub(super) struct SourceLayout<'a> {
    pub(super) owed: &'a HashSet<&'a str>,
    pub(super) marker: &'a str,
    pub(super) loc_width: usize,
    pub(super) content_width: usize,
    pub(super) term_width: usize,
    pub(super) colorize: bool,
    pub(super) card: bool,
}

/// Render one physical source row (a slice of a textual chunk). Colored: a
/// 1-char severity gutter, the line number, the code clipped to a fixed width
/// (with its match highlighted), then an aligned `// desc` comment. Plain (LLM):
/// the code verbatim, preceded — when it carries a finding — by a `{marker} SEV
/// LINE:COL DESC` annotation line. `byte_base`/`line_no`/`col_base` are the
/// absolute offset and 1-based source position of the row's first byte;
/// `cut_right` marks a row whose source line continues past the captured window.
pub(super) fn render_source_line(out: &mut String, row: &SourceRow<'_>, layout: &SourceLayout<'_>) {
    let SourceRow {
        data,
        byte_base,
        line_no,
        col_base,
        cut_right,
        notes,
        comment,
    } = *row;
    let SourceLayout {
        owed,
        marker,
        loc_width,
        content_width,
        term_width,
        colorize,
        card,
    } = *layout;
    let raw = String::from_utf8_lossy(data);
    let base = byte_base;
    let loc_str = line_no.to_string();
    // A mid-line row (the chunk sliced into an ultra-long line) lost its left
    // side; a `cut_right` row loses its right — mark each with a `…` even when the
    // content itself fits the width.
    let cut_left = col_base > 1;

    if colorize {
        // Expand tabs to spaces so a character's count equals its display width
        // (otherwise tab-indented lines push the aligned comment column out), and
        // relocate the match spans through that expansion.
        let (display, map) = expand_tabs(&raw);
        let to_disp = |off: u64| -> Option<usize> {
            map.get(usize::try_from(off.checked_sub(base)?).ok()?)
                .copied()
        };

        if card {
            // Card rows carry no severity gutter — the tinted comment marker
            // is the severity carrier — and the line number is left-justified
            // so every row's first digit shares a column.
            out.push_str(CARD_ROW_LEAD);
            out.push_str(&format!("{loc_str:<loc_width$}").bright_black().to_string());
        } else {
            let top = notes
                .iter()
                .copied()
                .max_by_key(|n| (n.crit, std::cmp::Reverse(n.off)));
            // Gutter and line number read as one unit — no space between them.
            out.push_str(&gutter_glyph(top.map(|n| n.crit), true));
            out.push_str(&format!("{loc_str:>loc_width$}").bright_black().to_string());
        }
        out.push_str("  ");

        // Clip the code to the fixed content column so comments line up, keeping
        // the primary match in view.
        let match_byte = notes.first().and_then(|n| to_disp(n.off));
        let (b0, b1, win_lead, win_trail) = source_window(&display, content_width, match_byte);
        let (lead, trail) = (win_lead || cut_left, win_trail || cut_right);
        let slice = display.get(b0..b1).unwrap_or("");
        let spans: Vec<(usize, usize, Criticality)> = notes
            .iter()
            .filter_map(|n| {
                let ds = to_disp(n.off)?;
                let de = to_disp(n.off + u64::from(n.len))?;
                (ds < b1 && de > b0).then(|| (ds.max(b0) - b0, de.min(b1) - b0, n.crit))
            })
            .collect();
        let mut visible = 0usize;
        if lead {
            out.push_str(&"…".bright_black().to_string());
            visible += 1;
        }
        if notes.is_empty() {
            out.push_str(&slice.bright_black().to_string()); // pure context: quiet gray
        } else {
            out.push_str(&paint_spans(slice, spans));
        }
        visible += slice.chars().count();
        if trail {
            out.push_str(&"…".bright_black().to_string());
            visible += 1;
        }

        if let Some(n) = comment {
            out.push_str(&" ".repeat(content_width.saturating_sub(visible) + 2));
            let (r, g, b) = crit_rgb(n.crit);
            let prefix = if card {
                CARD_ROW_LEAD.len() + loc_width + 2
            } else {
                src_prefix(loc_width)
            };
            let used = prefix + content_width + 2 + marker.chars().count() + 1;
            // 2-col right margin so the line never reaches the terminal edge.
            let budget = term_width.saturating_sub(used + 2).max(8);
            out.push_str(&marker.truecolor(r, g, b).to_string());
            out.push(' ');
            out.push_str(
                &truncate_with_ellipsis(&terse_description(&n.desc), budget)
                    .bright_white()
                    .to_string(),
            );
        }
        out.push('\n');
        return;
    }

    // Plain (LLM) view: a finding is announced on its own comment-marker line —
    //   {marker} SEV LINE:COL - DESC
    // placed immediately *before* the source row it describes, which then renders
    // verbatim (windowed to a fixed width, `...` marking any trim) with no prefix
    // or trailer. Keeping the code clear of cleave's columns lets the model read it
    // as the file's own source; the preceding annotation — comment marker, a single
    // severity letter, the location, then the description — marks it unmistakably
    // as cleave's detection, not text from the file. COL is the 1-based column of
    // the strongest match, offset by the row's own starting column (a mid-line
    // slice of a long line starts past column 1). Context and component rows carry
    // no annotation and render as bare source.
    let (display, map) = expand_tabs(&raw);
    let to_disp = |off: u64| -> Option<usize> {
        map.get(usize::try_from(off.checked_sub(base)?).ok()?)
            .copied()
    };
    let match_disp = comment.and_then(|n| to_disp(n.off));

    // The strongest note leads; every other owed note on the row — a
    // suspicious/hostile atom, or the leg of a withheld composite (see
    // `evidence_legs`), whatever its grade — follows on its own line. Keeping
    // only the strongest hid the rest of the row's evidence from the reader.
    let owes = |n: &Note| owed.contains(n.id.as_str());
    let mut announced: Vec<&Note> = comment
        .filter(|&n| n.crit >= Criticality::Notable || owes(n))
        .into_iter()
        .collect();
    for &n in notes {
        if owes(n) && announced.iter().all(|a| a.id != n.id) {
            announced.push(n);
        }
    }
    for n in announced {
        out.push_str(marker);
        out.push(' ');
        out.push(n.crit.letter());
        out.push(' ');
        out.push_str(&loc_str);
        if let Some(col) = to_disp(n.off)
            .map(|b| col_base + display.get(..b).map_or(0, |s| s.chars().count() as u64))
        {
            out.push(':');
            out.push_str(&col.to_string());
        }
        out.push(' ');
        out.push_str(&annotate_desc(&terse_description(&n.desc), &n.id));
        out.push('\n');
    }

    let (b0, b1, win_lead, win_trail) = source_window(&display, content_width, match_disp);
    let (lead, trail) = (win_lead || cut_left, win_trail || cut_right);
    let slice = display.get(b0..b1).unwrap_or("");
    if lead {
        out.push_str("...");
    }
    out.push_str(slice);
    if trail {
        out.push_str("...");
    }
    out.push('\n');
}

/// How every window of one binary file's hex context is laid out.
#[derive(Clone, Copy)]
pub(super) struct HexLayout<'a> {
    /// The finding ids selected for display.
    pub(super) sel: &'a HashSet<&'a str>,
    /// Bytes per hex row.
    pub(super) stride: usize,
    pub(super) marker: &'a str,
    pub(super) loc_width: usize,
    pub(super) term_width: usize,
    pub(super) opts: &'a TinyOpts,
    pub(super) colorize: bool,
}

/// Render one binary window: wrap its raw bytes into `stride`-byte hex|ascii
/// rows, highlight the matched bytes, and trail each row that carries a match
/// with a tinted `// desc` aligned in a hex-editor gutter. The comment is
/// truncated to the remaining terminal width so a row never wraps.
pub(super) fn render_hex_unit(
    out: &mut String,
    line: &ContextLine,
    notes: &[Note],
    layout: &HexLayout<'_>,
) {
    let HexLayout {
        sel,
        stride,
        marker,
        loc_width,
        term_width,
        opts,
        colorize,
    } = *layout;
    let full_context = opts.full_context;
    // Row trimming and the selected-notes filter below are cleave's terminal
    // view alone; every other consumer of this renderer keeps the window and
    // the annotations it asked for.
    let trim = is_terminal_view(opts);
    // Focused mode — and the terminal view — narrow this renderer's world to
    // the selected notes: they drive the byte highlights, the row filter, and
    // the gutter comments. A merged capture window then no longer annotates
    // unselected neighbors, whose rows (a language token, a file extension)
    // came with a margin each and buried the finding the window was drawn for.
    let notes: Vec<&Note> = notes
        .iter()
        .filter(|n| (opts.focus_crit.is_none() && !trim) || sel.contains(n.id.as_str()))
        .collect();
    let spans: Vec<(u64, u64, Criticality)> = notes
        .iter()
        .map(|n| (n.off, n.off + u64::from(n.len.max(1)), n.crit))
        .collect();
    // Display width of a full row's cells: `stride` `"XX "` triples, a
    // separator space, then `stride` ascii chars. A short final row pads its
    // comment up to this so trailers align like a hex editor's annotation gutter.
    let cells_w = stride * 3 + 1 + stride;
    // Column where the comment text starts, and the width left for it. A 2-col
    // right margin keeps the line clear of the terminal edge (no wrap). The
    // card layout swaps the severity gutter for a 3-space lead (one wider).
    let prefix = if opts.card {
        CARD_ROW_LEAD.len() + loc_width + 2
    } else {
        row_prefix(loc_width)
    };
    let comment_col = prefix + cells_w + 2 + marker.len() + 1;
    let desc_budget = term_width.saturating_sub(comment_col + 2).max(8);

    // Matches intersecting each row, strongest first — drives the gutter.
    let row_notes_by_row: Vec<Vec<&Note>> = (0..line.data.len())
        .step_by(stride)
        .map(|chunk_start| {
            let row_base = line.loc + chunk_start as u64;
            let row_end = row_base + (stride.min(line.data.len() - chunk_start)) as u64;
            let mut row_notes: Vec<&Note> = notes
                .iter()
                .copied()
                .filter(|n| n.off < row_end && row_base < n.off + u64::from(n.len.max(1)))
                .collect();
            row_notes.sort_by(|a, b| b.crit.cmp(&a.crit).then_with(|| a.off.cmp(&b.off)));
            row_notes
        })
        .collect();
    // Rows a match earned: the hit row itself plus a margin either side. One
    // row of neighbouring bytes is what places a match in its surroundings; a
    // hostile hit earns two, since its verdict most depends on what runs
    // alongside it. Capture reserves a criticality-sized byte window (up to
    // 128/256 bytes), which drawn whole turned a single hit into a twenty-row
    // block — the annotations scrolled away from the bytes they described.
    let mut margin_keep = vec![false; row_notes_by_row.len()];
    if trim {
        for (i, ns) in row_notes_by_row.iter().enumerate() {
            let Some(top) = ns.iter().map(|n| n.crit).max() else {
                continue;
            };
            let margin = if top >= Criticality::Hostile {
                HEX_MARGIN_HOSTILE
            } else {
                HEX_MARGIN_ROWS
            };
            let lo = i.saturating_sub(margin);
            let hi = (i + margin + 1).min(margin_keep.len());
            margin_keep[lo..hi].fill(true);
        }
    }

    // In focused mode a hit at or above `focus_crit` keeps one row of trailing
    // context — but only when the hit itself fit on a single row. A match span
    // that already continues onto a second row has shown its continuation;
    // adding a third row past it is padding. `hit_rows` counts the consecutive
    // rendered rows of the current hit; a trail fires only from exactly one.
    let mut hit_rows = 0usize;
    for (idx, chunk_start) in (0..line.data.len()).step_by(stride).enumerate() {
        let row = &line.data[chunk_start..(chunk_start + stride).min(line.data.len())];
        let row_base = line.loc + chunk_start as u64;
        let row_end = row_base + row.len() as u64;
        let row_notes = &row_notes_by_row[idx];
        let trail_here = row_notes.is_empty() && hit_rows == 1;
        // A note-less row inside some hit's margin; only the full-context views
        // draw these at all (an embedding host shows hit rows only).
        let margin_here = full_context && row_notes.is_empty() && (!trim || margin_keep[idx]);
        if row_notes.is_empty() {
            hit_rows = 0;
        } else if opts
            .focus_crit
            .is_some_and(|fc| row_notes.iter().any(|n| n.crit >= fc))
        {
            hit_rows += 1;
        } else {
            hit_rows = 0;
        }
        // Without surrounding context (an embedding host), emit only rows that carry a
        // match — full rows, just none of the padding rows around them — plus
        // the single trailing row a one-row focused hit earned. With it, the
        // margin rows around each hit (the terminal view: nothing further).
        if row_notes.is_empty() && !trail_here && !margin_here {
            continue;
        }
        // A short trailing row (the leftover tail of the captured context) is a
        // ragged stub. Drop it when it carries no match so every rendered row is
        // full and the columns line up; a note-bearing tail is kept and padded to
        // full width below (the wider trailing capture means notes rarely land
        // here, but a match at end-of-file still can).
        if row.len() < stride && row_notes.is_empty() && !trail_here {
            continue;
        }
        // The comment shows once, on the row where the match begins — not
        // repeated down every row its bytes span.
        let comment = row_notes
            .iter()
            .copied()
            .find(|n| n.off >= row_base && n.off < row_end);
        let loc_str = format!("{row_base:x}");

        if colorize {
            if opts.card {
                // Card rows carry no severity gutter — the tinted comment
                // marker is the severity carrier — and the location column is
                // left-justified so every row's first digit shares a column.
                out.push_str(CARD_ROW_LEAD);
                out.push_str(&format!("{loc_str:<loc_width$}").bright_black().to_string());
            } else {
                let top = row_notes
                    .iter()
                    .copied()
                    .max_by_key(|n| (n.crit, std::cmp::Reverse(n.off)));
                out.push_str(&gutter_glyph(top.map(|n| n.crit), true));
                out.push(' ');
                out.push_str(&format!("{loc_str:>loc_width$}").bright_black().to_string());
            }
            out.push_str("  ");
            let (cells, width) = hex_cells(row, row_base, &spans, stride, true);
            out.push_str(&cells);
            if let Some(n) = comment {
                let pad = cells_w.saturating_sub(width) + 2;
                out.push_str(&" ".repeat(pad));
                let (r, g, b) = crit_rgb(n.crit);
                out.push_str(&marker.truecolor(r, g, b).to_string());
                out.push(' ');
                let desc = truncate_with_ellipsis(&terse_description(&n.desc), desc_budget);
                out.push_str(&desc.bright_white().to_string());
            }
            out.push('\n');
        } else {
            out.push_str(&loc_str);
            out.push(if row_notes.is_empty() { '-' } else { ':' });
            out.push(' ');
            let (cells, _) = hex_cells(row, row_base, &spans, stride, false);
            out.push_str(&cells);
            if let Some(n) = comment {
                out.push_str(&format!(
                    "  {marker} {} {}",
                    n.crit.letter(),
                    annotate_desc(&terse_description(&n.desc), &n.id)
                ));
            }
            out.push('\n');
        }
    }
}

/// Build a hex|ascii row from raw bytes, highlighting matched bytes (both the
/// hex pair and its ascii) in the severity hue. Returns the rendered string and
/// its display width (independent of color codes), so a short final row can pad
/// its comment to the full grid.
pub(super) fn hex_cells(
    row: &[u8],
    row_base: u64,
    spans: &[(u64, u64, Criticality)],
    stride: usize,
    colorize: bool,
) -> (String, usize) {
    let crit_at = |i: usize| {
        let off = row_base + i as u64;
        spans
            .iter()
            .find(|&&(lo, hi, _)| lo <= off && off < hi)
            .map(|&(_, _, c)| c)
    };
    let mut s = String::new();
    for (i, &b) in row.iter().enumerate() {
        let pair = format!("{b:02x} ");
        match (colorize, crit_at(i)) {
            (true, Some(c)) => {
                let (r, g, bl) = crit_rgb(c);
                s.push_str(&pair.truecolor(r, g, bl).bold().to_string());
            }
            (true, None) => s.push_str(&pair.bright_black().to_string()),
            (false, _) => s.push_str(&pair),
        }
    }
    // Pad the hex column to the full stride so a short row's ascii and comment
    // still align with full rows (each missing byte cell is `"XX "` = 3 cols).
    for _ in row.len()..stride {
        s.push_str("   ");
    }
    s.push(' '); // separator between hex and ascii columns
    for (i, &b) in row.iter().enumerate() {
        let ch = if b.is_ascii_graphic() || b == b' ' {
            b as char
        } else {
            '.'
        };
        match (colorize, crit_at(i)) {
            (true, Some(c)) => {
                let (r, g, bl) = crit_rgb(c);
                s.push_str(&ch.to_string().truecolor(r, g, bl).bold().to_string());
            }
            (true, None) => s.push_str(&ch.to_string().bright_black().to_string()),
            (false, _) => s.push(ch),
        }
    }
    // Width reflects the full-stride hex column plus the row's own ascii chars;
    // the caller pads the comment by the remaining ascii shortfall.
    (s, stride * 3 + 1 + row.len())
}

/// The theme's truecolor for a criticality — the brand severity palette (coral /
/// gold / azure / forest / gray). The line body is painted in this hue regular,
/// the matched evidence the same hue bold.
pub(super) fn crit_rgb(crit: Criticality) -> (u8, u8, u8) {
    match crit {
        Criticality::Hostile => crate::theme::HOSTILE_RGB,
        Criticality::Suspicious => crate::theme::SUSPICIOUS_RGB,
        Criticality::Notable => crate::theme::NOTABLE_RGB,
        Criticality::Baseline => crate::theme::BASELINE_RGB,
        _ => crate::theme::COMPONENT_RGB,
    }
}

/// Paint `text` with the theme severity painter (hostile/suspicious bold).
pub(super) fn paint_by_crit(crit: Criticality, text: &str) -> colored::ColoredString {
    match crit {
        Criticality::Hostile => crate::theme::paint_hostile(text),
        Criticality::Suspicious => crate::theme::paint_suspicious(text),
        Criticality::Notable => crate::theme::paint_notable(text),
        Criticality::Baseline => crate::theme::paint_baseline(text),
        _ => crate::theme::paint_component(text),
    }
}
