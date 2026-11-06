//! Decoded script layers: PowerShell -EncodedCommand, variation-selector payloads, deobfuscation and batch expansion.

// Split out of the parent module for size; it shares the parent's namespace.
#[allow(clippy::wildcard_imports)]
use super::*;

pub(super) const PS_KEYWORDS: &[&str] = &[
    "Invoke-Expression",
    "IEX",
    "New-Object",
    "Add-Type",
    "Import-Module",
    "Start-Process",
    "DownloadString",
    "DownloadFile",
    "WebClient",
    "powershell",
    "PowerShell",
    "bypass",
    "EncodedCommand",
];

pub(super) const ENC_FLAGS: &[&str] = &[
    "-EncodedCommand",
    "-encodedcommand",
    "-EncodedC",
    "-enc ",
    "-Enc ",
    " -ec ",
];

pub(super) fn extract_ps_encoded_arg(s: &str) -> Option<&str> {
    for flag in ENC_FLAGS {
        if let Some(pos) = s.find(flag) {
            let after = s[pos + flag.len()..].trim_start();
            let end = after
                .find(|c: char| c.is_whitespace() || c == '"' || c == '\'')
                .unwrap_or(after.len());
            let blob = &after[..end];
            if blob.len() >= 40 {
                return Some(blob);
            }
        }
    }
    None
}

pub(super) fn decode_utf16le(base64_blob: &str) -> Option<String> {
    let clean = strip_whitespace(base64_blob);
    let bytes = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, &clean).ok()?;
    if bytes.len() % 2 != 0 {
        return None;
    }
    let wide: Vec<u16> = bytes
        .as_chunks::<2>()
        .0
        .iter()
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .collect();
    String::from_utf16(&wide).ok()
}

pub(super) fn has_ps_keywords(s: &str) -> bool {
    PS_KEYWORDS.iter().filter(|&&kw| s.contains(kw)).count() >= 2
}

pub(super) fn file_type_for_script_language(language: &str) -> Option<FileType> {
    match language {
        "python" => Some(FileType::Python),
        "javascript" => Some(FileType::JavaScript),
        "php" => Some(FileType::Php),
        "powershell" => Some(FileType::PowerShell),
        "lua" => Some(FileType::Lua),
        "vbscript" => Some(FileType::Vbs),
        _ => None,
    }
}

pub(super) fn encoding_chain_for_deobfuscation(
    result: &stng::script::DeobfuscationResult,
) -> Vec<String> {
    if result.language == stng::script::detect::ScriptLanguage::PowerShell
        && result.chain_description.contains("utf16le")
    {
        vec!["base64-utf16le".to_string()]
    } else {
        vec!["script".to_string()]
    }
}

/// Cheap gate so we do not re-run stng's deobfuscator regexes on every
/// clean source member. stng already ran them during string extract;
/// this second pass only exists to keep `DeobfuscationResult.decoded`
/// as a whole layer instead of shredded `ScriptDecode` fragments.
pub(super) fn host_may_contain_script_obfuscation(content: &str) -> bool {
    const NEEDLES: &[&str] = &[
        "#@~^",
        "@(",
        "EncodedCommand",
        "encodedcommand",
        "-EncodedC",
        "-enc ",
        "-Enc ",
        " -ec ",
        "FromBase64String",
        "b64decode",
        "base64_decode",
        "atob(",
        "atob (",
        "eval(",
        "String.fromCharCode",
        "zlib.decompress",
        "fromhex",
        "codecs.decode",
        "marshal.loads",
        "gzinflate",
        "str_rot13",
        "Invoke-Expression",
        "iex(",
        "IEX(",
    ];
    (content.contains("__builtins__") && content.contains("copyright.__str__"))
        || ((content.contains("5578712") || content.contains("5145329"))
            && content.contains("charAt"))
        || NEEDLES.iter().any(|needle| content.contains(*needle))
        || content
            .as_bytes()
            .windows(7)
            .any(|w| w.eq_ignore_ascii_case(b"execute"))
        || stng::script::detect::detect_script_language(content.as_bytes())
            == Some(stng::script::detect::ScriptLanguage::Lua)
}

pub(super) fn encoded_powershell_finding(
    parent_path: &str,
    decoded_len: usize,
    offset: u64,
) -> Finding {
    Finding {
        precomputed_spans: None,
        src: None,
        kind: FindingKind::Capability,
        id: "binary/embedded/base64-powershell".to_string().into(),
        desc: format!(
            "PowerShell -EncodedCommand payload ({} chars decoded) at offset {:#x}",
            decoded_len, offset
        )
        .into(),
        conf: 0.95,
        // Encoding a PowerShell command does not establish hostile intent;
        // the decoded layer's findings supply any stronger evidence.
        crit: Criticality::Notable,
        mbc: None,
        attack: Some("T1059.001".into()),
        evidence: vec![Evidence {
            method: "base64_utf16le_decode".to_string(),
            source: "embedded_code_detector".to_string(),
            value: format!("decoded_chars={}", decoded_len),
            location: Some(format!("offset:{:#x}", offset)),
            ..Default::default()
        }],
        match_count: 1,
        trait_refs: vec![],
        source_file: Some(parent_path.to_string()),
        downgraded: false,
    }
}

/// Decode a Unicode variation-selector steganography payload.
///
/// Variation selectors render as nothing, so a run of them carries bytes
/// invisibly inside what looks like an ordinary string literal. Every
/// published implementation uses the same mapping, and so does the malware:
/// `U+FE00..=U+FE0F` gives 0..=15 and `U+E0100..=U+E01EF` gives 16..=255.
///
/// Both spellings have to be handled. A minified bundle usually stores the
/// payload as literal `\u{E0148}` escape text -- the compromised
/// watercrawl-mcp and miso-client releases are pure ASCII on disk for exactly
/// that reason -- while a hand-written file may carry the real codepoints.
/// Scanning only for the characters misses the form that actually ships.
///
/// Returns the longest decoded run and its byte offset, or `None` when no run
/// is long enough to be a payload rather than a stray selector after an emoji.
pub(super) fn decode_variation_selector_payload(content: &str) -> Option<(String, usize)> {
    /// Short runs are legitimate: one selector follows an emoji or a CJK
    /// glyph to pick a presentation form. A payload is hundreds of bytes.
    const MIN_PAYLOAD_BYTES: usize = 64;

    fn byte_for(cp: u32) -> Option<u8> {
        if (0xFE00..=0xFE0F).contains(&cp) {
            u8::try_from(cp - 0xFE00).ok()
        } else if (0xE0100..=0xE01EF).contains(&cp) {
            u8::try_from(cp - 0xE0100 + 16).ok()
        } else {
            None
        }
    }

    // Read a literal `\u{HEX}` escape at `idx`, returning the codepoint and
    // the length of the escape text consumed.
    fn escape_at(bytes: &[u8], idx: usize) -> Option<(u32, usize)> {
        if bytes.get(idx) != Some(&b'\\') || bytes.get(idx + 1) != Some(&b'u') {
            return None;
        }
        if bytes.get(idx + 2) != Some(&b'{') {
            return None;
        }
        let close = bytes[idx + 3..].iter().position(|b| *b == b'}')? + idx + 3;
        let hex = std::str::from_utf8(&bytes[idx + 3..close]).ok()?;
        if hex.is_empty() || hex.len() > 6 {
            return None;
        }
        let cp = u32::from_str_radix(hex, 16).ok()?;
        Some((cp, close + 1 - idx))
    }

    let bytes = content.as_bytes();
    let mut best: Option<(usize, Vec<u8>)> = None;
    let mut run: Vec<u8> = Vec::new();
    let mut run_start = 0usize;
    let mut idx = 0usize;

    let flush = |run: &mut Vec<u8>, start: usize, best: &mut Option<(usize, Vec<u8>)>| {
        if run.len() >= MIN_PAYLOAD_BYTES
            && best.as_ref().is_none_or(|(_, prev)| run.len() > prev.len())
        {
            *best = Some((start, std::mem::take(run)));
        } else {
            run.clear();
        }
    };

    while idx < bytes.len() {
        let (cp, width) = match escape_at(bytes, idx) {
            Some(hit) => hit,
            None => match content[idx..].chars().next() {
                Some(ch) => (ch as u32, ch.len_utf8()),
                None => break,
            },
        };
        match byte_for(cp) {
            Some(b) => {
                if run.is_empty() {
                    run_start = idx;
                }
                run.push(b);
            }
            None => flush(&mut run, run_start, &mut best),
        }
        idx += width;
    }
    flush(&mut run, run_start, &mut best);

    let (offset, payload) = best?;
    let text = String::from_utf8(payload).ok()?;
    Some((text, offset))
}

/// Analyze a stng-decoded script payload as its own source layer.
pub(crate) fn analyze_decoded_script_layer(
    parent_path: &str,
    decoded: &str,
    offset: u64,
    file_type: FileType,
    encoding_chain: Vec<String>,
    engine: &crate::Engine,
    current_depth: usize,
    emit_encoded_powershell: bool,
) -> Option<FileAnalysis> {
    if current_depth >= MAX_DECODE_DEPTH || decoded.len() < MIN_ENCODED_SIZE {
        return None;
    }
    // Keep EncodedCommand paths on the historical hex-offset form so existing
    // `##base64-utf16le@0x…` layers compare against B2. Other script payloads
    // use the shared decoded-path encoder.
    let virtual_path = if emit_encoded_powershell {
        format!("{}##base64-utf16le@{:#x}", parent_path, offset)
    } else {
        encode_decoded_path(parent_path, &encoding_chain, offset as usize)
    };

    // Language comes from stng's deobfuscator (or the EncodedCommand
    // fallback), not the virtual path — force the grammar.
    let mut report = if let Some(analyzer) = UnifiedSourceAnalyzer::for_file_type(&file_type) {
        analyzer
            .with_engine(engine.clone())
            .without_embedded_detection()
            .with_encoded_context(encoding_chain.clone())
            .analyze_source_as_configured(Path::new(&virtual_path), decoded)
    } else if file_type == FileType::Vbs {
        super::super::generic::GenericAnalyzer::new(file_type)
            .with_engine(engine.clone())
            .without_embedded_detection()
            .analyze_source_as_configured(Path::new(&virtual_path), decoded)
    } else if file_type == FileType::Batch {
        super::super::generic::GenericAnalyzer::new(file_type)
            .with_engine(engine.clone())
            .analyze_source_as_configured(Path::new(&virtual_path), decoded)
    } else {
        return None;
    };

    if emit_encoded_powershell {
        report.findings.push(encoded_powershell_finding(
            parent_path,
            decoded.len(),
            offset,
        ));
    }

    let (mut entry, _, _) = report.into_file_analysis(0, engine);
    entry.path = virtual_path;
    entry.depth = (current_depth + 1) as u32;
    entry.encoding = Some(encoding_chain);
    entry.compute_summary();
    Some(entry)
}

/// Turn `stng::script::deobfuscate_script` payloads into embed layers.
///
/// This is the non-duplicate work: stng already found and decoded the
/// blobs (and shreds them into `ScriptDecode` fragments for string
/// matching). Cleave still needs the *full* decoded text as a typed
/// source layer so AST/trait rules see the payload, not the fragments.
pub(crate) fn analyze_script_deobfuscation_layers(
    parent_path: &str,
    content: &str,
    engine: &crate::Engine,
    current_depth: usize,
    cancelled: Option<&AtomicBool>,
) -> Vec<FileAnalysis> {
    if current_depth >= MAX_DECODE_DEPTH || !host_may_contain_script_obfuscation(content) {
        return Vec::new();
    }

    let mut layers = Vec::new();
    for (offset, decoded, language) in super::super::literal_program::decode(content) {
        let Some(file_type) = file_type_for_script_language(language) else {
            continue;
        };
        if let Some(layer) = analyze_decoded_script_layer(
            parent_path,
            &decoded,
            offset as u64,
            file_type,
            vec![format!("{language}-literal-program")],
            engine,
            current_depth,
            false,
        ) {
            layers.push(layer);
        }
    }
    for result in stng::script::deobfuscate_script(content.as_bytes()) {
        if cancelled.is_some_and(|flag| flag.load(Ordering::Acquire)) {
            break;
        }
        let Some(file_type) = file_type_for_script_language(result.language.as_str()) else {
            continue;
        };
        let encoding_chain = encoding_chain_for_deobfuscation(&result);
        let emit_encoded_powershell = file_type == FileType::PowerShell
            && encoding_chain.iter().any(|step| step == "base64-utf16le");
        if let Some(layer) = analyze_decoded_script_layer(
            parent_path,
            &result.decoded,
            result.offset as u64,
            file_type,
            encoding_chain,
            engine,
            current_depth,
            emit_encoded_powershell,
        ) {
            layers.push(layer);
        }
    }

    // Variation-selector steganography is not something stng deobfuscates, and
    // the trait engine cannot reach a payload it never sees decoded: the
    // watercrawl-mcp and miso-client compromises hid an AES-encrypted Solana
    // command-and-control stage this way, and the shipped bundle exposed only
    // the decoder and an eval.
    if let Some((decoded, offset)) = decode_variation_selector_payload(content)
        && let Some(layer) = analyze_decoded_script_layer(
            parent_path,
            &decoded,
            offset as u64,
            FileType::JavaScript,
            vec!["unicode-variation-selector".to_string()],
            engine,
            current_depth,
            false,
        )
    {
        layers.push(layer);
    }

    layers
}

/// Replay cmd's `set`/`%var%` expansion over a batch script and analyze the
/// result as its own batch layer.
///
/// Set-fragment obfuscation (`set ;{=ove /y` then `m%;{%`) leaves no command
/// word in the file as written; the expanded layer is where `move`, `format`
/// and `deltree` become visible to text rules. The layer is not re-expanded.
pub(crate) fn analyze_batch_expansion_layer(
    parent_path: &str,
    content: &[u8],
    engine: &crate::Engine,
) -> Option<FileAnalysis> {
    const ENCODING: &str = "batch-expansion";
    if parent_path.contains(ENCODING) {
        return None;
    }
    let result = stng::script::expand_batch_variables(content)?;
    let encoding_chain = vec![ENCODING.to_string()];
    let virtual_path = encode_decoded_path(parent_path, &encoding_chain, result.offset);
    let analyzer =
        super::super::generic::GenericAnalyzer::new(FileType::Batch).with_engine(engine.clone());
    let mut report =
        analyzer.analyze_source_as_configured(Path::new(&virtual_path), &result.decoded);
    report.findings.extend(generate_encoded_layer_traits(
        &encoding_chain,
        result.offset as u64,
    ));
    let (mut entry, _, _) = report.into_file_analysis(0, engine);
    entry.path = virtual_path;
    entry.depth = 1;
    entry.encoding = Some(encoding_chain);
    entry.compute_summary();
    Some(entry)
}

/// Detect and decode a PowerShell -EncodedCommand blob in `value`.
///
/// Fallback for binary/generic hosts that never ran source-tier script
/// deobfuscation. Unified source analysis uses
/// [`analyze_script_deobfuscation_layers`] instead.
pub(super) fn detect_powershell_encoded_command(
    parent_path: &str,
    value: &str,
    offset: u64,
    engine: &crate::Engine,
    current_depth: usize,
) -> Option<FileAnalysis> {
    let blob = extract_ps_encoded_arg(value)?;
    let decoded = decode_utf16le(blob)?;
    if !has_ps_keywords(&decoded) {
        return None;
    }
    analyze_decoded_script_layer(
        parent_path,
        &decoded,
        offset,
        FileType::PowerShell,
        vec!["base64-utf16le".to_string()],
        engine,
        current_depth,
        true,
    )
}
