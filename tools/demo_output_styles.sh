#!/usr/bin/env bash
# Preview ideas for clearer cleave CLI output.
#   ./tools/demo_output_styles.sh                     # all demos
#   ./tools/demo_output_styles.sh 0 1 combo           # subset
#   0..5    flatter / file-level ideas
#   6..10   section-preserving ideas (OBJ / MB / META remain first-class)

set -euo pipefail

# palette — mirrors src/output.rs (bright_* via colored crate)
DIM=$'\033[90m'     ; WHITE=$'\033[97m'   ; BOLD=$'\033[1m'
RED=$'\033[91m'     ; YEL=$'\033[93m'     ; GRN=$'\033[92m'
MAG=$'\033[95m'     ; CYAN=$'\033[96m'    ; BLUE=$'\033[94m'
RST=$'\033[0m'

COLS=$(tput cols 2>/dev/null || echo 120)

# reverse-video section pills (demo 10)
MAG_BG=$'\033[1;97;45m'     # bold white on magenta
BLUE_BG=$'\033[1;97;44m'    # bold white on blue
GRAY_BG=$'\033[1;97;100m'   # bold white on dark gray

# ── primitives ───────────────────────────────────────────────────────────────

banner() {
    local n=$1 title=$2
    printf '\n%b%s%b\n' "$DIM" "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" "$RST"
    printf '  %bDEMO %s%b  %b%s%b\n' "$BOLD$CYAN" "$n" "$RST" "$BOLD$WHITE" "$title" "$RST"
    printf '%b%s%b\n\n' "$DIM" "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" "$RST"
}

note() { printf '  %b%s%b\n\n' "$DIM" "$1" "$RST"; }

rule() {
    printf '%b%s%b\n' "$DIM" "──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────" "$RST"
}

fhead()      { printf '%b%b%s%b  %b%s%b\n\n' "$WHITE" "$BOLD" "$1" "$RST" "$DIM" "detected: $2" "$RST"; }

# fhead_strong: file header that outweighs any section treatment.
#   Leading blank + bold white path + dim "detected:" line, then a full-width heavy ━ rule
#   in cyan (a hue no section treatment uses), then trailing blank. 4 lines of signature
#   reads as "FILE" level from anywhere on the page, even scrolling at 100 pages of output.
fhead_strong() {
    local path=$1 meta=$2
    printf '\n%b%b%s%b  %b%s%b\n' "$WHITE" "$BOLD" "$path" "$RST" "$DIM" "detected: $meta" "$RST"
    printf '\033[36m%s\033[0m\n' "$(_fill "$COLS" '━')"
}

# fhead_bare: like fhead_strong but drops the "detected:" prefix — used for polished demo 10
fhead_bare() {
    local path=$1 meta=$2
    printf '\n%b%b%s%b  %b%s%b\n' "$WHITE" "$BOLD" "$path" "$RST" "$DIM" "$meta" "$RST"
    printf '\033[36m%s\033[0m\n' "$(_fill "$COLS" '━')"
}
fhead_tree() {
    printf '%b▼%b %b%b%s%b\n'  "$CYAN" "$RST" "$WHITE" "$BOLD" "$1" "$RST"
    printf '%b│%b  %b%s%b\n'   "$DIM"  "$RST" "$DIM"   "detected: $2" "$RST"
}
fhead_idx()  { printf '%b%s%b %b%b%s%b  %b%s%b\n\n' "$BOLD$CYAN" "$1" "$RST" "$WHITE" "$BOLD" "$2" "$RST" "$DIM" "detected: $3" "$RST"; }

sect()      { printf '%b%b%s%b\n' "$MAG" "$BOLD" "$1" "$RST"; }
sect_rail() { printf '%b│%b  %b%b%s%b\n' "$DIM" "$RST" "$MAG" "$BOLD" "$1" "$RST"; }

# fill N chars of a repeated glyph
_fill() { local n=$1 ch=$2 s=""; (( n < 1 )) && { printf ''; return; }; for ((i=0;i<n;i++)); do s+="$ch"; done; printf '%s' "$s"; }

# sect_trail: "OBJECTIVES ─────────────────…" name + trailing rule to edge
sect_trail() {
    local name=$1
    local pad=$(( COLS - ${#name} - 1 ))
    printf '%b%b%s%b %b%s%b\n' "$MAG" "$BOLD" "$name" "$RST" "$DIM" "$(_fill "$pad" "─")" "$RST"
}

# sect_leader: plain UPPERCASE magenta bold, no trailing decoration
sect_leader() {
    printf '%b%b%s%b\n' "$MAG" "$BOLD" "$1" "$RST"
}

# sect_bracket: quiet lowercase with middle-dot prefix — "· objectives"
sect_bracket() {
    printf '%b· %s%b\n' "$DIM" "$1" "$RST"
}

# sect_pill: reverse-video tab — " OBJECTIVES "
# arg1=namespace (obj|mb|meta) arg2=name
sect_pill() {
    local bg=$GRAY_BG
    case "$1" in obj) bg=$MAG_BG ;; mb) bg=$BLUE_BG ;; esac
    printf '%b %s %b\n' "$bg" "$2" "$RST"
}

# sect_pill_tight: pill hugs the letters — zero inner padding, minimum footprint
sect_pill_tight() {
    local bg=$GRAY_BG
    case "$1" in obj) bg=$MAG_BG ;; mb) bg=$BLUE_BG ;; esac
    printf '%b%s%b\n' "$bg" "$2" "$RST"
}

# sect_bar: colored ▌ block + neutral bold uppercase — typographic, no bg fill
sect_bar() {
    local c=$DIM
    case "$1" in obj) c=$MAG ;; mb) c=$BLUE ;; esac
    printf '%b▌%b %b%s%b\n' "$c" "$RST" "$BOLD" "$2" "$RST"
}

# sect_underline: bold uppercase with ANSI underline in section color — no bg
sect_underline() {
    local code="1;4;90"   # bold + underline + dim default
    case "$1" in obj) code="1;4;95" ;; mb) code="1;4;94" ;; esac
    printf '\033[%sm%s\033[0m\n' "$code" "$2"
}

# sect_pill_muted: same structure as sect_pill but darker 256-color backgrounds
sect_pill_muted() {
    local idx=236                          # dark gray default
    case "$1" in obj) idx=53 ;; mb) idx=17 ;; esac
    printf '\033[1;97;48;5;%sm %s \033[0m\n' "$idx" "$2"
}

# sect_pill_litmus: truecolor pill with semantic hue per section —
#   well-known=red (concrete threat), objectives=orange (intent),
#   behaviors=green (operational), metadata=grey (ambient).
sect_pill_litmus() {
    local rgb="95;0;0"                                  # wellknown: red
    case "$1" in
        obj)  rgb="95;55;0"  ;;                         # orange
        mb)   rgb="0;80;30"  ;;                         # green
        meta) rgb="48;48;48" ;;                         # grey
    esac
    printf '\033[1;97;48;2;%sm %s \033[0m\n' "$rgb" "$2"
}

# tline_tag TAG BUL CRIT TRAIT DESC EV — 12-char left tag column (full namespace names)
tline_tag() {
    local col; col=$(_crit_color "$3")
    printf '%b%-12s%b%b%s%b %-38s  %-54s  %b%s%b\n' "$DIM" "$1" "$RST" "$col" "$2" "$RST" "$4" "$5" "$col" "$6" "$RST"
}

# crit → color lookup
_crit_color() {
    case "$1" in 2) printf '%s' "$RED" ;; 1) printf '%s' "$YEL" ;; *) printf '%s' "$GRN" ;; esac
}

# tline BUL CRIT TRAIT DESC EV          — current flat style
tline() {
    local col; col=$(_crit_color "$2")
    printf '%b%s%b %-45s  %-54s  %b%s%b\n' "$col" "$1" "$RST" "$3" "$4" "$col" "$5" "$RST"
}

# tline_rail — same, gutter prefix
tline_rail() {
    local col; col=$(_crit_color "$2")
    printf '%b│%b  %b%s%b %-45s  %-54s  %b%s%b\n' "$DIM" "$RST" "$col" "$1" "$RST" "$3" "$4" "$col" "$5" "$RST"
}

# tline_glyph GLYPH GCOLOR BUL CRIT TRAIT DESC EV — namespace glyph + crit bullet
tline_glyph() {
    local gc=$DIM col; col=$(_crit_color "$4")
    case "$2" in mag) gc=$MAG ;; blue) gc=$BLUE ;; esac
    printf '  %b%s%b  %b%s%b %-45s  %-54s  %b%s%b\n' "$gc" "$1" "$RST" "$col" "$3" "$RST" "$5" "$6" "$col" "$7" "$RST"
}

# tline_idx INDEX BUL CRIT TRAIT DESC EV — file-index sigil prefix
tline_idx() {
    local col; col=$(_crit_color "$3")
    printf '  %b%s·%b  %b%s%b %-45s  %-54s  %b%s%b\n' "$DIM" "$1" "$RST" "$col" "$2" "$RST" "$4" "$5" "$col" "$6" "$RST"
}

# ── demo 0: baseline (current renderer) ──────────────────────────────────────
demo0() {
    banner "0" "Baseline — current renderer, for reference"
    fhead "/tmp/extract/Lib/site-packages/Crypto/Hash/_MD5.pyd" "PE • O(Al₂)H(Cr)Md"
    sect "OBJECTIVES"
    tline " ••" 1 "anti-analysis/debugger-detect/heuristics"    "Malware with multiple anti-analysis awareness checks" "IsDebuggerPresent, QueryPerformanceCounter, IsProcessorFeature…"
    tline " ••" 1 "anti-analysis/vm-detect/processor-features"  "Check processor features (potential VM detection)"    "IsProcessorFeaturePresent"
    echo
    sect "MICRO-BEHAVIORS"
    tline "  •" 0 "crypto/kdf/operations"                       "PBKDF2 key derivation"                                "MD5_pbkdf2_hmac_assist"
    echo
    sect "METADATA"
    tline "  •" 0 "metadata/unsigned"                           "Binary is not digitally signed"                       ""
    echo
    fhead "/tmp/extract/Lib/site-packages/Crypto/Hash/_MD4.pyd" "PE • O(Al₂)Md"
    sect "OBJECTIVES"
    tline " ••" 1 "anti-analysis/debugger-detect/heuristics"    "Malware with multiple anti-analysis awareness checks" "IsProcessorFeaturePresent, IsDebuggerPresent, QueryPerformance…"
    tline " ••" 1 "anti-analysis/vm-detect/processor-features"  "Check processor features (potential VM detection)"    "IsProcessorFeaturePresent"
    echo
    sect "METADATA"
    tline "  •" 0 "metadata/unsigned"                           "Binary is not digitally signed"                       ""
    echo
}

# ── demo 1: tree gutter + hairline rule ──────────────────────────────────────
demo1() {
    banner "1" "Tree gutter + hairline rule between files"
    note "Continuous │ rail per file, rule between. Two chars of decoration, unmistakable boundaries."
    fhead_tree "/tmp/extract/Lib/site-packages/Crypto/Hash/_MD5.pyd" "PE • O(Al₂)H(Cr)Md"
    sect_rail "OBJECTIVES"
    tline_rail " ••" 1 "anti-analysis/debugger-detect/heuristics"    "Malware with multiple anti-analysis awareness checks" "IsDebuggerPresent, QueryPerformanceCounter, IsProcessorFeature…"
    tline_rail " ••" 1 "anti-analysis/vm-detect/processor-features"  "Check processor features (potential VM detection)"    "IsProcessorFeaturePresent"
    sect_rail "MICRO-BEHAVIORS"
    tline_rail "  •" 0 "crypto/kdf/operations"                       "PBKDF2 key derivation"                                "MD5_pbkdf2_hmac_assist"
    sect_rail "METADATA"
    tline_rail "  •" 0 "metadata/unsigned"                           "Binary is not digitally signed"                       ""
    rule
    fhead_tree "/tmp/extract/Lib/site-packages/Crypto/Hash/_MD4.pyd" "PE • O(Al₂)Md"
    sect_rail "OBJECTIVES"
    tline_rail " ••" 1 "anti-analysis/debugger-detect/heuristics"    "Malware with multiple anti-analysis awareness checks" "IsProcessorFeaturePresent, IsDebuggerPresent, QueryPerformance…"
    tline_rail " ••" 1 "anti-analysis/vm-detect/processor-features"  "Check processor features (potential VM detection)"    "IsProcessorFeaturePresent"
    sect_rail "METADATA"
    tline_rail "  •" 0 "metadata/unsigned"                           "Binary is not digitally signed"                       ""
    rule
    echo
}

# ── demo 2: inline namespace glyphs replace section headers ──────────────────
demo2() {
    banner "2" "Inline namespace glyphs — no section headers"
    note "◆ objective  ▸ micro-behavior  · metadata. Saves ~4 lines/file; grouping survives via the glyph column."
    fhead "/tmp/extract/Lib/site-packages/Crypto/Hash/_MD5.pyd" "PE • O(Al₂)H(Cr)Md"
    tline_glyph "◆" mag  " ••" 1 "anti-analysis/debugger-detect/heuristics"    "Malware with multiple anti-analysis awareness checks" "IsDebuggerPresent, QueryPerformanceCounter, IsProcessorFeature…"
    tline_glyph "◆" mag  " ••" 1 "anti-analysis/vm-detect/processor-features"  "Check processor features (potential VM detection)"    "IsProcessorFeaturePresent"
    tline_glyph "▸" blue "  •" 0 "crypto/kdf/operations"                       "PBKDF2 key derivation"                                "MD5_pbkdf2_hmac_assist"
    tline_glyph "·" dim  "  •" 0 "metadata/unsigned"                           "Binary is not digitally signed"                       ""
    echo
    fhead "/tmp/extract/Lib/site-packages/Crypto/Hash/_MD4.pyd" "PE • O(Al₂)Md"
    tline_glyph "◆" mag  " ••" 1 "anti-analysis/debugger-detect/heuristics"    "Malware with multiple anti-analysis awareness checks" "IsProcessorFeaturePresent, IsDebuggerPresent, QueryPerformance…"
    tline_glyph "◆" mag  " ••" 1 "anti-analysis/vm-detect/processor-features"  "Check processor features (potential VM detection)"    "IsProcessorFeaturePresent"
    tline_glyph "·" dim  "  •" 0 "metadata/unsigned"                           "Binary is not digitally signed"                       ""
    echo
}

# ── demo 3: file-index sigil on every line ───────────────────────────────────
demo3() {
    banner "3" "File-index sigil — every row knows its parent"
    note "Numbered files ①②③ with a faded ①· prefix on each trait. Scroll back N screens, attribution still holds."
    fhead_idx "①" "/tmp/extract/Lib/site-packages/Crypto/Hash/_MD5.pyd" "PE • O(Al₂)H(Cr)Md"
    tline_idx "①" " ••" 1 "anti-analysis/debugger-detect/heuristics"    "Malware with multiple anti-analysis awareness checks" "IsDebuggerPresent, QueryPerformanceCounter, +3"
    tline_idx "①" " ••" 1 "anti-analysis/vm-detect/processor-features"  "Check processor features (potential VM detection)"    "IsProcessorFeaturePresent"
    tline_idx "①" "  •" 0 "crypto/kdf/operations"                       "PBKDF2 key derivation"                                "MD5_pbkdf2_hmac_assist"
    tline_idx "①" "  •" 0 "metadata/unsigned"                           "Binary is not digitally signed"                       ""
    echo
    fhead_idx "②" "/tmp/extract/Lib/site-packages/Crypto/Hash/_MD4.pyd" "PE • O(Al₂)Md"
    tline_idx "②" " ••" 1 "anti-analysis/debugger-detect/heuristics"    "Malware with multiple anti-analysis awareness checks" "IsProcessorFeaturePresent, IsDebuggerPresent, +2"
    tline_idx "②" " ••" 1 "anti-analysis/vm-detect/processor-features"  "Check processor features (potential VM detection)"    "IsProcessorFeaturePresent"
    tline_idx "②" "  •" 0 "metadata/unsigned"                           "Binary is not digitally signed"                       ""
    echo
    fhead_idx "③" "/tmp/extract/Lib/site-packages/Crypto/Hash/SHA512.py" "PYTHON • H(Cr)"
    tline_idx "③" "  •" 0 "crypto/kdf/operations"                       "PBKDF2 key derivation"                                "PBKDF2"
    echo
}

# ── demo 4: smart evidence overflow ──────────────────────────────────────────
demo4() {
    banner "4" "Smart evidence overflow — explicit +N, rank by distinctiveness"
    printf '  %bbefore — opaque ellipsis truncation%b\n' "$DIM" "$RST"
    tline " ••" 1 "anti-analysis/debugger-detect/heuristics"   "Malware with multiple anti-analysis awareness checks" "IsDebuggerPresent, QueryPerformanceCounter, IsProcessorFeature…"
    echo
    printf '  %bafter — explicit overflow count%b\n' "$DIM" "$RST"
    tline " ••" 1 "anti-analysis/debugger-detect/heuristics"   "Malware with multiple anti-analysis awareness checks" "IsDebuggerPresent, QueryPerformanceCounter, +3"
    echo
    printf '  %bafter — ranked by distinctiveness, then +N%b\n' "$DIM" "$RST"
    tline " ••" 1 "anti-analysis/debugger-detect/heuristics"   "Malware with multiple anti-analysis awareness checks" "RtlGenRandom, GetSystemFirmwareTable, +3"
    echo
    printf '  %blong evidence list becomes compact%b\n' "$DIM" "$RST"
    tline "  •" 0 "crypto/kdf/operations"                      "PBKDF2 key derivation"                                "PKCS5_v2_PBKDF2_keyivgen, PKCS5_pbkdf2_set_ex, +3"
    echo
}

# ── demo 5: cross-file rollup ────────────────────────────────────────────────
demo5() {
    banner "5" "Cross-file rollup — fold universal traits into a footer"
    note "Suppress traits that fire on most files inline; surface them once as a shared footer. What's left per-file is what's distinctive."
    fhead "/tmp/extract/Lib/site-packages/Crypto/Hash/_MD5.pyd" "PE • O(Al₂)H(Cr)Md"
    sect "OBJECTIVES"
    tline " ••" 1 "anti-analysis/debugger-detect/heuristics"    "Malware with multiple anti-analysis awareness checks" "IsDebuggerPresent, QueryPerformanceCounter, +3"
    tline " ••" 1 "anti-analysis/vm-detect/processor-features"  "Check processor features (potential VM detection)"    "IsProcessorFeaturePresent"
    echo
    fhead "/tmp/extract/Lib/site-packages/Crypto/Hash/_MD4.pyd" "PE • O(Al₂)Md"
    sect "OBJECTIVES"
    tline " ••" 1 "anti-analysis/debugger-detect/heuristics"    "Malware with multiple anti-analysis awareness checks" "IsProcessorFeaturePresent, IsDebuggerPresent, +2"
    tline " ••" 1 "anti-analysis/vm-detect/processor-features"  "Check processor features (potential VM detection)"    "IsProcessorFeaturePresent"
    echo
    fhead "/tmp/extract/Lib/site-packages/Crypto/Hash/SHA512.py" "PYTHON • H(Cr)"
    printf '  %b(no distinctive traits — see shared footer)%b\n\n' "$DIM" "$RST"
    fhead "/tmp/extract/Lib/site-packages/Crypto/Hash/_ghash_clmul.pyd" "PE • Md"
    printf '  %b(no distinctive traits — see shared footer)%b\n\n' "$DIM" "$RST"
    printf '%b shared across scan %b %bmetadata/unsigned%b %b×3%b  %b·%b  %bcrypto/kdf/operations%b %b×3%b\n\n' \
        "$DIM" "$RST" "$GRN" "$RST" "$DIM" "$RST" "$DIM" "$RST" "$GRN" "$RST" "$DIM" "$RST"
}

# ── combo: tree rail + glyphs + overflow + rollup ────────────────────────────
democombo() {
    banner "★" "Combined — rail + inline glyphs + smart overflow + rollup"
    fhead_tree "/tmp/extract/Lib/site-packages/Crypto/Hash/_MD5.pyd" "PE • O(Al₂)H(Cr)Md"
    printf '%b│%b  ' "$DIM" "$RST"; tline_glyph "◆" mag  " ••" 1 "anti-analysis/debugger-detect/heuristics"    "Malware with multiple anti-analysis awareness checks" "IsDebuggerPresent, QueryPerformanceCounter, +3"
    printf '%b│%b  ' "$DIM" "$RST"; tline_glyph "◆" mag  " ••" 1 "anti-analysis/vm-detect/processor-features"  "Check processor features (potential VM detection)"    "IsProcessorFeaturePresent"
    printf '%b│%b  ' "$DIM" "$RST"; tline_glyph "▸" blue "  •" 0 "crypto/kdf/operations"                       "PBKDF2 key derivation"                                "MD5_pbkdf2_hmac_assist"
    rule
    fhead_tree "/tmp/extract/Lib/site-packages/Crypto/Hash/_MD4.pyd" "PE • O(Al₂)Md"
    printf '%b│%b  ' "$DIM" "$RST"; tline_glyph "◆" mag  " ••" 1 "anti-analysis/debugger-detect/heuristics"    "Malware with multiple anti-analysis awareness checks" "IsProcessorFeaturePresent, IsDebuggerPresent, +2"
    printf '%b│%b  ' "$DIM" "$RST"; tline_glyph "◆" mag  " ••" 1 "anti-analysis/vm-detect/processor-features"  "Check processor features (potential VM detection)"    "IsProcessorFeaturePresent"
    rule
    fhead_tree "/tmp/extract/DLLs/libcrypto-3.dll" "PE • O(Co)H₃(Cm₃Cr₆Po₂)Md(Si)"
    printf '%b│%b  ' "$DIM" "$RST"; tline_glyph "◆" mag  "  •" 0 "collection/file-targeting/filter"            "PEM certificate/key (.pem) extension"                 ".pem"
    printf '%b│%b  ' "$DIM" "$RST"; tline_glyph "▸" blue "  •" 0 "communications/http/headers"                 "Basic authentication"                                 "Authorization: Basic"
    printf '%b│%b  ' "$DIM" "$RST"; tline_glyph "▸" blue "  •" 0 "communications/socket/init"                  "Winsock socket creation import"                       "ORDINAL 23, WS2_32.dll"
    printf '%b│%b  ' "$DIM" "$RST"; tline_glyph "▸" blue "  •" 0 "crypto/asymmetric/rsa"                       "RSA_public_decrypt reference"                         "RSA_public_decrypt"
    printf '%b│%b  ' "$DIM" "$RST"; tline_glyph "▸" blue "  •" 0 "crypto/hash/digest"                          "SHA256 hashing functions"                             "SHA256_Init, SHA256_Update, +2"
    printf '%b│%b  ' "$DIM" "$RST"; tline_glyph "▸" blue "  •" 0 "crypto/library"                              "OpenSSL EVP encryption functions"                     "EVP_CipherInit_ex, AES_cbc_encrypt, +2"
    printf '%b│%b  ' "$DIM" "$RST"; tline_glyph "▸" blue "  •" 0 "crypto/symmetric/aes"                        "AES S-box start bytes"                                "63 7C 77 7B F2 6B 6F C5"
    printf '%b│%b  ' "$DIM" "$RST"; tline_glyph "▸" blue "  •" 0 "crypto/symmetric/stream"                     "ChaCha20/Salsa20 cipher constant"                     "expand 32-byte k"
    printf '%b│%b  ' "$DIM" "$RST"; tline_glyph "▸" blue " ••" 1 "process/enumerate/snapshot"                  "Dynamic Toolhelp enumeration suite"                   "Module32First, Module32Next, +1"
    printf '%b│%b  ' "$DIM" "$RST"; tline_glyph "·" dim  "  •" 0 "metadata/signed/leaf"                        "Signed by Python Software Foundation"                 "Python Software Foundation"
    rule
    printf '%b shared across scan %b %bmetadata/unsigned%b %b×3%b  %b·%b  %bcrypto/kdf/operations%b %b×3%b\n\n' \
        "$DIM" "$RST" "$GRN" "$RST" "$DIM" "$RST" "$DIM" "$RST" "$GRN" "$RST" "$DIM" "$RST"
}

# ════════════════════════════════════════════════════════════════════════════
#   Section-preserving family — sections stay first-class, but quieter
# ════════════════════════════════════════════════════════════════════════════

# ── demo 6: UPPERCASE header + trailing rule to edge ─────────────────────────
demo6() {
    banner "6" "Trailing rule — header name + hair rule to the edge"
    note "Files: cyan ━ under-rule reads 'FILE' level from anywhere. Sections: magenta name + dim ─ hair rule to the edge. Different line weights = different hierarchy levels."
    fhead_strong "/tmp/extract/Lib/site-packages/Crypto/Hash/_MD5.pyd" "PE • O(Al₂)H(Cr)Md"
    sect_trail "OBJECTIVES"
    tline " ••" 1 "anti-analysis/debugger-detect/heuristics"    "Malware with multiple anti-analysis awareness checks" "IsDebuggerPresent, QueryPerformanceCounter, +3"
    tline " ••" 1 "anti-analysis/vm-detect/processor-features"  "Check processor features (potential VM detection)"    "IsProcessorFeaturePresent"
    echo
    sect_trail "MICRO-BEHAVIORS"
    tline "  •" 0 "crypto/kdf/operations"                       "PBKDF2 key derivation"                                "MD5_pbkdf2_hmac_assist"
    echo
    sect_trail "METADATA"
    tline "  •" 0 "metadata/unsigned"                           "Binary is not digitally signed"                       ""
    fhead_strong "/tmp/extract/Lib/site-packages/Crypto/Hash/_MD4.pyd" "PE • O(Al₂)Md"
    sect_trail "OBJECTIVES"
    tline " ••" 1 "anti-analysis/debugger-detect/heuristics"    "Malware with multiple anti-analysis awareness checks" "IsProcessorFeaturePresent, IsDebuggerPresent, +2"
    tline " ••" 1 "anti-analysis/vm-detect/processor-features"  "Check processor features (potential VM detection)"    "IsProcessorFeaturePresent"
    echo
    sect_trail "METADATA"
    tline "  •" 0 "metadata/unsigned"                           "Binary is not digitally signed"                       ""
    fhead_strong "/tmp/extract/DLLs/libcrypto-3.dll" "PE • O(Co)H₃(Cm₃Cr₆Po₂)Md(Si)"
    sect_trail "OBJECTIVES"
    tline "  •" 0 "collection/file-targeting/filter"            "PEM certificate/key (.pem) extension"                 ".pem"
    echo
    sect_trail "MICRO-BEHAVIORS"
    tline "  •" 0 "communications/http/headers"                 "Basic authentication"                                 "Authorization: Basic"
    tline "  •" 0 "communications/socket/init"                  "Winsock socket creation import"                       "ORDINAL 23, WS2_32.dll"
    tline "  •" 0 "crypto/asymmetric/rsa"                       "RSA_public_decrypt reference"                         "RSA_public_decrypt"
    tline "  •" 0 "crypto/hash/digest"                          "SHA256 hashing functions"                             "SHA256_Init, SHA256_Update, +2"
    tline "  •" 0 "crypto/library"                              "OpenSSL EVP encryption functions"                     "EVP_CipherInit_ex, AES_cbc_encrypt, +2"
    tline "  •" 0 "crypto/symmetric/aes"                        "AES S-box start bytes"                                "63 7C 77 7B F2 6B 6F C5"
    tline "  •" 0 "crypto/symmetric/stream"                     "ChaCha20/Salsa20 cipher constant"                     "expand 32-byte k"
    tline " ••" 1 "process/enumerate/snapshot"                  "Dynamic Toolhelp enumeration suite"                   "Module32First, Module32Next, +1"
    echo
    sect_trail "METADATA"
    tline "  •" 0 "metadata/signed/leaf"                        "Signed by Python Software Foundation"                 "Python Software Foundation"
    echo
}

# ── demo 7: mixed-case header with dot-leader + right-aligned count ──────────
demo7() {
    banner "7" "Dot-leader + count — typographic, TOC-like"
    note "Files: cyan ━ under-rule (heavy, opaque). Sections: dim · · · · leader (light, transparent). Opposite visual textures keep file > section unambiguous at scroll speed."
    fhead_strong "/tmp/extract/Lib/site-packages/Crypto/Hash/_MD5.pyd" "PE • O(Al₂)H(Cr)Md"
    sect_leader "OBJECTIVES"
    tline " ••" 1 "anti-analysis/debugger-detect/heuristics"    "Malware with multiple anti-analysis awareness checks" "IsDebuggerPresent, QueryPerformanceCounter, +3"
    tline " ••" 1 "anti-analysis/vm-detect/processor-features"  "Check processor features (potential VM detection)"    "IsProcessorFeaturePresent"
    sect_leader "MICRO-BEHAVIORS"
    tline "  •" 0 "crypto/kdf/operations"                       "PBKDF2 key derivation"                                "MD5_pbkdf2_hmac_assist"
    sect_leader "METADATA"
    tline "  •" 0 "metadata/unsigned"                           "Binary is not digitally signed"                       ""
    fhead_strong "/tmp/extract/Lib/site-packages/Crypto/Hash/_MD4.pyd" "PE • O(Al₂)Md"
    sect_leader "OBJECTIVES"
    tline " ••" 1 "anti-analysis/debugger-detect/heuristics"    "Malware with multiple anti-analysis awareness checks" "IsProcessorFeaturePresent, IsDebuggerPresent, +2"
    tline " ••" 1 "anti-analysis/vm-detect/processor-features"  "Check processor features (potential VM detection)"    "IsProcessorFeaturePresent"
    sect_leader "METADATA"
    tline "  •" 0 "metadata/unsigned"                           "Binary is not digitally signed"                       ""
    fhead_strong "/tmp/extract/DLLs/libcrypto-3.dll" "PE • O(Co)H₃(Cm₃Cr₆Po₂)Md(Si)"
    sect_leader "OBJECTIVES"
    tline "  •" 0 "collection/file-targeting/filter"            "PEM certificate/key (.pem) extension"                 ".pem"
    sect_leader "MICRO-BEHAVIORS"
    tline "  •" 0 "communications/http/headers"                 "Basic authentication"                                 "Authorization: Basic"
    tline "  •" 0 "communications/socket/init"                  "Winsock socket creation import"                       "ORDINAL 23, WS2_32.dll"
    tline "  •" 0 "crypto/asymmetric/rsa"                       "RSA_public_decrypt reference"                         "RSA_public_decrypt"
    tline "  •" 0 "crypto/hash/digest"                          "SHA256 hashing functions"                             "SHA256_Init, SHA256_Update, +2"
    tline "  •" 0 "crypto/library"                              "OpenSSL EVP encryption functions"                     "EVP_CipherInit_ex, AES_cbc_encrypt, +2"
    tline "  •" 0 "crypto/symmetric/aes"                        "AES S-box start bytes"                                "63 7C 77 7B F2 6B 6F C5"
    tline "  •" 0 "crypto/symmetric/stream"                     "ChaCha20/Salsa20 cipher constant"                     "expand 32-byte k"
    tline " ••" 1 "process/enumerate/snapshot"                  "Dynamic Toolhelp enumeration suite"                   "Module32First, Module32Next, +1"
    sect_leader "METADATA"
    tline "  •" 0 "metadata/signed/leaf"                        "Signed by Python Software Foundation"                 "Python Software Foundation"
    echo
}

# ── demo 8: hanging tag column — section implied by column-left transitions ──
demo8() {
    banner "8" "Hanging tag column — lowercase 4-char tag in the left margin"
    note "Files: cyan ━ under-rule. Sections: quiet lowercase tag in a 5-char left column; it shows only on a section's first row. Tag transitions = section boundary, file rule = file boundary — two different axes, two different hierarchies."
    fhead_strong "/tmp/extract/Lib/site-packages/Crypto/Hash/_MD5.pyd" "PE • O(Al₂)H(Cr)Md"
    tline_tag "objectives"  " ••" 1 "anti-analysis/debugger-detect/heuristics"    "Malware with multiple anti-analysis awareness checks" "IsDebuggerPresent, QueryPerformanceCounter, +3"
    tline_tag ""     " ••" 1 "anti-analysis/vm-detect/processor-features"  "Check processor features (potential VM detection)"    "IsProcessorFeaturePresent"
    tline_tag "behaviors"   "  •" 0 "crypto/kdf/operations"                       "PBKDF2 key derivation"                                "MD5_pbkdf2_hmac_assist"
    tline_tag "metadata"  "  •" 0 "metadata/unsigned"                           "Binary is not digitally signed"                       ""
    fhead_strong "/tmp/extract/Lib/site-packages/Crypto/Hash/_MD4.pyd" "PE • O(Al₂)Md"
    tline_tag "objectives"  " ••" 1 "anti-analysis/debugger-detect/heuristics"    "Malware with multiple anti-analysis awareness checks" "IsProcessorFeaturePresent, IsDebuggerPresent, +2"
    tline_tag ""     " ••" 1 "anti-analysis/vm-detect/processor-features"  "Check processor features (potential VM detection)"    "IsProcessorFeaturePresent"
    tline_tag "metadata"  "  •" 0 "metadata/unsigned"                           "Binary is not digitally signed"                       ""
    fhead_strong "/tmp/extract/DLLs/libcrypto-3.dll" "PE • O(Co)H₃(Cm₃Cr₆Po₂)Md(Si)"
    tline_tag "objectives"  "  •" 0 "collection/file-targeting/filter"            "PEM certificate/key (.pem) extension"                 ".pem"
    tline_tag "behaviors"   "  •" 0 "communications/http/headers"                 "Basic authentication"                                 "Authorization: Basic"
    tline_tag ""     "  •" 0 "communications/socket/init"                  "Winsock socket creation import"                       "ORDINAL 23, WS2_32.dll"
    tline_tag ""     "  •" 0 "crypto/asymmetric/rsa"                       "RSA_public_decrypt reference"                         "RSA_public_decrypt"
    tline_tag ""     "  •" 0 "crypto/hash/digest"                          "SHA256 hashing functions"                             "SHA256_Init, SHA256_Update, +2"
    tline_tag ""     "  •" 0 "crypto/library"                              "OpenSSL EVP encryption functions"                     "EVP_CipherInit_ex, AES_cbc_encrypt, +2"
    tline_tag ""     "  •" 0 "crypto/symmetric/aes"                        "AES S-box start bytes"                                "63 7C 77 7B F2 6B 6F C5"
    tline_tag ""     "  •" 0 "crypto/symmetric/stream"                     "ChaCha20/Salsa20 cipher constant"                     "expand 32-byte k"
    tline_tag ""     " ••" 1 "process/enumerate/snapshot"                  "Dynamic Toolhelp enumeration suite"                   "Module32First, Module32Next, +1"
    tline_tag "metadata"  "  •" 0 "metadata/signed/leaf"                        "Signed by Python Software Foundation"                 "Python Software Foundation"
    echo
}

# ── demo 9: bracket-wrapped compact header with count ────────────────────────
demo9() {
    banner "9" "Bracket-wrapped — quiet, lowercase, inline count"
    note "Files: cyan ━ under-rule (loud). Sections: dim [ name · count ] (quietest of all). Maximum contrast between the two hierarchies — file reads first, sections recede."
    fhead_strong "/tmp/extract/Lib/site-packages/Crypto/Hash/_MD5.pyd" "PE • O(Al₂)H(Cr)Md"
    sect_bracket "objectives"
    tline " ••" 1 "anti-analysis/debugger-detect/heuristics"    "Malware with multiple anti-analysis awareness checks" "IsDebuggerPresent, QueryPerformanceCounter, +3"
    tline " ••" 1 "anti-analysis/vm-detect/processor-features"  "Check processor features (potential VM detection)"    "IsProcessorFeaturePresent"
    sect_bracket "micro-behaviors"
    tline "  •" 0 "crypto/kdf/operations"                       "PBKDF2 key derivation"                                "MD5_pbkdf2_hmac_assist"
    sect_bracket "metadata"
    tline "  •" 0 "metadata/unsigned"                           "Binary is not digitally signed"                       ""
    fhead_strong "/tmp/extract/Lib/site-packages/Crypto/Hash/_MD4.pyd" "PE • O(Al₂)Md"
    sect_bracket "objectives"
    tline " ••" 1 "anti-analysis/debugger-detect/heuristics"    "Malware with multiple anti-analysis awareness checks" "IsProcessorFeaturePresent, IsDebuggerPresent, +2"
    tline " ••" 1 "anti-analysis/vm-detect/processor-features"  "Check processor features (potential VM detection)"    "IsProcessorFeaturePresent"
    sect_bracket "metadata"
    tline "  •" 0 "metadata/unsigned"                           "Binary is not digitally signed"                       ""
    fhead_strong "/tmp/extract/DLLs/libcrypto-3.dll" "PE • O(Co)H₃(Cm₃Cr₆Po₂)Md(Si)"
    sect_bracket "objectives"
    tline "  •" 0 "collection/file-targeting/filter"            "PEM certificate/key (.pem) extension"                 ".pem"
    sect_bracket "micro-behaviors"
    tline "  •" 0 "communications/http/headers"                 "Basic authentication"                                 "Authorization: Basic"
    tline "  •" 0 "communications/socket/init"                  "Winsock socket creation import"                       "ORDINAL 23, WS2_32.dll"
    tline "  •" 0 "crypto/asymmetric/rsa"                       "RSA_public_decrypt reference"                         "RSA_public_decrypt"
    tline "  •" 0 "crypto/hash/digest"                          "SHA256 hashing functions"                             "SHA256_Init, SHA256_Update, +2"
    tline "  •" 0 "crypto/library"                              "OpenSSL EVP encryption functions"                     "EVP_CipherInit_ex, AES_cbc_encrypt, +2"
    tline "  •" 0 "crypto/symmetric/aes"                        "AES S-box start bytes"                                "63 7C 77 7B F2 6B 6F C5"
    tline "  •" 0 "crypto/symmetric/stream"                     "ChaCha20/Salsa20 cipher constant"                     "expand 32-byte k"
    tline " ••" 1 "process/enumerate/snapshot"                  "Dynamic Toolhelp enumeration suite"                   "Module32First, Module32Next, +1"
    sect_bracket "metadata"
    tline "  •" 0 "metadata/signed/leaf"                        "Signed by Python Software Foundation"                 "Python Software Foundation"
    echo
}

# ── demo 10 family: pill tabs + variations ───────────────────────────────────
# All five share _pill_body; only the section renderer differs.

_pill_body() {
    local sf=$1
    fhead_bare "/tmp/extract/Lib/site-packages/Crypto/Hash/_MD5.pyd" "PE • O(Al₂)H(Cr)Md"
    $sf obj "OBJECTIVES"
    tline " ••" 1 "anti-analysis/debugger-detect/heuristics"    "Malware with multiple anti-analysis awareness checks" "IsDebuggerPresent, QueryPerformanceCounter, +3"
    tline " ••" 1 "anti-analysis/vm-detect/processor-features"  "Check processor features (potential VM detection)"    "IsProcessorFeaturePresent"
    echo
    $sf mb "MICRO-BEHAVIORS"
    tline "  •" 0 "crypto/kdf/operations"                       "PBKDF2 key derivation"                                "MD5_pbkdf2_hmac_assist"
    echo
    $sf meta "METADATA"
    tline "  •" 0 "metadata/unsigned"                           "Binary is not digitally signed"                       ""
    fhead_bare "/tmp/extract/Lib/site-packages/Crypto/Hash/_MD4.pyd" "PE • O(Al₂)Md"
    $sf obj "OBJECTIVES"
    tline " ••" 1 "anti-analysis/debugger-detect/heuristics"    "Malware with multiple anti-analysis awareness checks" "IsProcessorFeaturePresent, IsDebuggerPresent, +2"
    tline " ••" 1 "anti-analysis/vm-detect/processor-features"  "Check processor features (potential VM detection)"    "IsProcessorFeaturePresent"
    echo
    $sf meta "METADATA"
    tline "  •" 0 "metadata/unsigned"                           "Binary is not digitally signed"                       ""
    fhead_bare "/tmp/extract/DLLs/libcrypto-3.dll" "PE • O(Co)H₃(Cm₃Cr₆Po₂)Md(Si)"
    $sf obj "OBJECTIVES"
    tline "  •" 0 "collection/file-targeting/filter"            "PEM certificate/key (.pem) extension"                 ".pem"
    echo
    $sf mb "MICRO-BEHAVIORS"
    tline "  •" 0 "communications/http/headers"                 "Basic authentication"                                 "Authorization: Basic"
    tline "  •" 0 "communications/socket/init"                  "Winsock socket creation import"                       "ORDINAL 23, WS2_32.dll"
    tline "  •" 0 "crypto/asymmetric/rsa"                       "RSA_public_decrypt reference"                         "RSA_public_decrypt"
    tline "  •" 0 "crypto/hash/digest"                          "SHA256 hashing functions"                             "SHA256_Init, SHA256_Update, +2"
    tline "  •" 0 "crypto/library"                              "OpenSSL EVP encryption functions"                     "EVP_CipherInit_ex, AES_cbc_encrypt, +2"
    tline "  •" 0 "crypto/symmetric/aes"                        "AES S-box start bytes"                                "63 7C 77 7B F2 6B 6F C5"
    tline "  •" 0 "crypto/symmetric/stream"                     "ChaCha20/Salsa20 cipher constant"                     "expand 32-byte k"
    tline " ••" 1 "process/enumerate/snapshot"                  "Dynamic Toolhelp enumeration suite"                   "Module32First, Module32Next, +1"
    echo
    $sf meta "METADATA"
    tline "  •" 0 "metadata/signed/leaf"                        "Signed by Python Software Foundation"                 "Python Software Foundation"
    echo
}

demo10() {
    banner "10" "Pill — reverse-video saturated bg (baseline)"
    note "Bright ANSI 45/44/100 backgrounds. The baseline pill look — loudest of the five."
    _pill_body sect_pill
}

demo11() {
    banner "11" "Variant: tight pill — zero inner padding"
    note "Background hugs the letters directly. Feels less like a 'tab' and more like a 'highlighted word'. Smallest footprint."
    _pill_body sect_pill_tight
}

demo12() {
    banner "12" "Variant: color bar — ▌ block in section color, neutral bold name"
    note "No background fill. The colored vertical block carries namespace identity; the text stays plain. Typographic, modern, lightest-weight."
    _pill_body sect_bar
}

demo13() {
    banner "13" "Variant: underlined name — no background, color via underline"
    note "Bold uppercase + ANSI underline in the section color. Pure typography — no pill, no bar. Quietest while still color-coded."
    _pill_body sect_underline
}

demo14() {
    banner "14" "Variant: muted palette — darker 256-color pills"
    note "Same pill structure as 10, but dark-magenta/blue/gray via 256-color. Softer, more modern-UI feel. Terminal-dependent."
    _pill_body sect_pill_muted
}

demo15() {
    banner "15" "Variant: semantic hues — red → orange → green → grey"
    note "Color carries meaning: well-known=red (concrete threat), objectives=orange (intent), behaviors=green (operational detail), metadata=grey (ambient). Demo fixture has no well-known, but that pill would render dark red at the top."
    _pill_body sect_pill_litmus
}

# ── dispatch ─────────────────────────────────────────────────────────────────

run() {
    case "$1" in
        0|base|baseline) demo0 ;;
        1) demo1 ;;
        2) demo2 ;;
        3) demo3 ;;
        4) demo4 ;;
        5) demo5 ;;
        6) demo6 ;;
        7) demo7 ;;
        8) demo8 ;;
        9) demo9 ;;
        10) demo10 ;;
        11) demo11 ;;
        12) demo12 ;;
        13) demo13 ;;
        14) demo14 ;;
        15) demo15 ;;
        c|combo|combined|'*') democombo ;;
        *) printf 'unknown demo: %s (use 0..15 or combo)\n' "$1" >&2; return 1 ;;
    esac
}

if [[ $# -eq 0 ]]; then
    demo0; demo1; demo2; demo3; demo4; demo5
    demo6; demo7; demo8; demo9; demo10
    demo11; demo12; demo13; demo14; demo15
    democombo
else
    for d in "$@"; do run "$d"; done
fi
