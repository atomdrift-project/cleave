#!/usr/bin/env bash
# diff_ui_palettes.sh — five color palette mockups for the cleave-diff
# layout. Each renders the same dataset (rand-user-agent clean →
# compromised, the DEV#POPPER campaign sample) so they can be compared
# at a glance.
#
# Goal: less garish than the bright-ANSI defaults, tonally consistent
# with `cleave analyze`'s pill+dot language, professional with a
# little fun. Modern terminal aesthetics (256-color and truecolor).
#
# Usage:
#   ./tools/diff_ui_palettes.sh           # render all 5
#   ./tools/diff_ui_palettes.sh slate     # one palette by name
#   ./tools/diff_ui_palettes.sh notes     # design notes only
#
# Palettes:
#   slate    — cool monochrome + amber accent (corporate / serious)
#   sienna   — warm earthy (rust, sage, sand)
#   lab      — modern dev tool (rose, peach, cyan on slate bg pills)
#   teal     — single-hue intensity gradient (focused)
#   carbon   — black & white + scarcity orange for hostile only

set -uo pipefail

# ───────────────────────────────────────────────────────────── shared esc ──
ESC=$'\033'
RST="${ESC}[0m"
BOLD="${ESC}[1m"
DIM="${ESC}[2m"
ITAL="${ESC}[3m"
UNDER="${ESC}[4m"

# ─────────────────────────────────────────────────────────────────── data ──
OLD="rand-user-agent/clean/index.js"
NEW="rand-user-agent/compromised/index.js"
ROC_OVERALL="73.1"
FILES_CHANGED="1"

# Traits (criticality | id | description) — the diff's headline findings
TRAIT_HOSTILE_1="malware/stealer/dev-popper::dev-popper-tag-pattern|DPRK DEV#POPPER campaign tag pattern"
TRAIT_SUSP_1="lang/javascript-features::global-alias-require|Aliasing require to a global variable"
TRAIT_SUSP_2="anti-static/obfuscation/string/encoding::js-version-marker|Malware version tracking pattern"
TRAIT_SUSP_3="anti-static/obfuscation/tools/js-obfuscator::global-bracket-require-alias|Require aliased to global via bracket notation"
TRAIT_NOTE_1="anti-static/obfuscation/eval/dynamic::export-iife-closure|Trailing IIFE closure indicating auto-execution"
TRAIT_BASE_1="anti-static/obfuscation/code-metrics/structure::high-text-entropy|High overall text entropy (encoded)"
TRAIT_BASE_2="data/source/syntax/keyword::js-keyword-xor|XOR bitwise operator in expression"

# Metrics (sign | path | percent | old → new) — show grouping
METRIC_S1="↑|strings.max_length|+14750%|24 → 3564"
METRIC_S2="↑|strings.total_bytes|+10414%|86B → 8.8KB"
METRIC_S3="↑|strings.avg_length|+2003%|8.60 → 180.84"
METRIC_T1="↑|text.max_line_length|+3473%|100 → 3573"
METRIC_T2="↑|text.line_length_stddev|+1338%|26.37 → 379.04"
METRIC_F1="↑|file.size|+489%|1.1KB → 6.2KB"
METRIC_I1="↑|imports.unique_modules|+100%|21 → 42"
METRIC_ID1="↑|identifiers.unique_count|+141%|17 → 41"

# Symbols (5 of 21 obfuscated imports)
SYMBOLS=("global._V" "global.r" "l.charAt" "pHg" "pHg.substr" "x.f" "x.join")
SYMBOLS_BREAKDOWN="21 → 42 symbols (+21 imports)"

# Strings — keep one pseudo-real and the cap footer
STRING_HIDDEN="21 low-signal added strings hidden"

WIDTH=${COLUMNS:-$(tput cols 2>/dev/null || echo 96)}
[[ "$WIDTH" -gt 100 ]] && WIDTH=100

# ─────────────────────────────────────────────────────────────── helpers ──
hr() {
  # Thin rule of given char to WIDTH, in given color
  local ch="${1:-─}" col="${2:-$DIM}"
  local rule
  rule=$(printf "%${WIDTH}s" "" | tr ' ' "$ch")
  printf "${col}%s${RST}\n" "$rule"
}

split_id() {
  # Echo "<short-id>"; strips the leading taxonomy directory like
  # the real diff renderer does (well-known/, objectives/, etc.).
  local id="$1"
  echo "$id"
}

# ──────────────────────────────────────────────────── palette 1: SLATE ────
# Cool monochrome + amber accent. Quiet, corporate, scannable.
# Severity encoded in font weight + amber emphasis on hostile.
slate() {
  local FG="${ESC}[38;5;252m"        # off-white
  local FG_DIM="${ESC}[38;5;245m"
  local FG_VDIM="${ESC}[38;5;240m"
  local SLATE="${ESC}[38;5;110m"     # cool blue-gray
  local SAND="${ESC}[38;5;179m"      # sand
  local AMBER="${ESC}[38;5;215m"     # warm amber
  local SAGE="${ESC}[38;5;108m"      # muted green
  local HOSTILE="${BOLD}${ESC}[38;5;174m"   # muted rose
  local SUSP="${BOLD}${ESC}[38;5;215m"      # warm amber
  local NOTE="${ESC}[38;5;110m"             # cool slate-blue
  local BASE="${ESC}[38;5;108m"             # sage
  local DOT_H="${HOSTILE}●●●${RST}"
  local DOT_S="${SUSP}●●${RST} "
  local DOT_N="${NOTE}● ${RST} "
  local DOT_B="${BASE}· ${RST} "

  printf "${BOLD}slate${RST} ${FG_DIM}— cool monochrome + amber accent${RST}\n"
  hr "─" "$FG_VDIM"
  printf "  ${FG_DIM}diff${RST}  ${FG}%s${RST} ${FG_DIM}→${RST} ${FG}%s${RST}\n" "$OLD" "$NEW"
  printf "        ${FG_DIM}ROC${RST} ${SUSP}${ROC_OVERALL}%%${RST}    ${FG_DIM}${FILES_CHANGED} file changed${RST}\n"
  echo
  printf "  ${HOSTILE}●●●${RST}  ${BOLD}88.9%%${RST}\n"
  printf "  ${FG_VDIM}$(printf '─%.0s' $(seq 1 $((WIDTH - 2))))${RST}\n"
  echo
  printf "  ${BOLD}traits${RST}  ${FG_DIM}[ROC: ${SUSP}99.6%%${FG_DIM}]  +20 -1${RST}\n"
  IFS='|' read -r id desc <<< "$TRAIT_HOSTILE_1"
  printf "    %s ${HOSTILE}+ %s${RST}\n        ${FG_DIM}%s${RST}\n" "$DOT_H" "$id" "$desc"
  for tr in "$TRAIT_SUSP_1" "$TRAIT_SUSP_2" "$TRAIT_SUSP_3"; do
    IFS='|' read -r id desc <<< "$tr"
    printf "    %s ${SUSP}+ %s${RST}\n        ${FG_DIM}%s${RST}\n" "$DOT_S" "$id" "$desc"
  done
  IFS='|' read -r id desc <<< "$TRAIT_NOTE_1"
  printf "    %s ${NOTE}+ %s${RST}\n        ${FG_DIM}%s${RST}\n" "$DOT_N" "$id" "$desc"
  IFS='|' read -r id desc <<< "$TRAIT_BASE_1"
  printf "    %s ${BASE}+ %s${RST}\n        ${FG_VDIM}%s${RST}\n" "$DOT_B" "$id" "$desc"
  echo
  printf "  ${BOLD}metrics${RST}  ${FG_DIM}[ROC: ${AMBER}56.8%%${FG_DIM}]  +20 ~52${RST}\n"
  printf "    ${FG_DIM}strings:${RST}\n"
  for m in "$METRIC_S1" "$METRIC_S2" "$METRIC_S3"; do
    IFS='|' read -r sgn path pct vals <<< "$m"
    printf "    ${AMBER}%s${RST} %-40s ${FG_DIM}%s${RST}   ${FG}%s${RST}\n" "$sgn" "$path" "$pct" "$vals"
  done
  echo
  printf "    ${FG_DIM}text:${RST}\n"
  for m in "$METRIC_T1" "$METRIC_T2"; do
    IFS='|' read -r sgn path pct vals <<< "$m"
    printf "    ${AMBER}%s${RST} %-40s ${FG_DIM}%s${RST}   ${FG}%s${RST}\n" "$sgn" "$path" "$pct" "$vals"
  done
  echo
  printf "    ${FG_DIM}file:${RST}\n"
  IFS='|' read -r sgn path pct vals <<< "$METRIC_F1"
  printf "    ${AMBER}%s${RST} %-40s ${FG_DIM}%s${RST}   ${FG}%s${RST}\n" "$sgn" "$path" "$pct" "$vals"
  echo
  printf "  ${BOLD}symbols${RST}  ${FG_DIM}[ROC: ${SAND}50.0%%${FG_DIM}]  +21${RST}\n"
  printf "    ${FG_DIM}%s${RST}\n" "$SYMBOLS_BREAKDOWN"
  for s in "${SYMBOLS[@]}"; do
    printf "    ${SAGE}+${RST} ${FG_DIM}[import]${RST} ${FG}%s${RST}\n" "$s"
  done
  echo
  printf "  ${BOLD}strings${RST}  ${FG_DIM}[ROC: ${AMBER}87.5%%${FG_DIM}]  +35${RST}\n"
  printf "    ${FG_VDIM}· %s${RST}\n" "$STRING_HIDDEN"
  printf "    ${SAGE}+${RST} ${FG}thnoywfmcbxturazrpeicolsodngcruqksvtj${RST}\n"
  printf "    ${SAGE}+${RST} ${FG}7-randuser84${RST}\n"
  echo
}

# ─────────────────────────────────────────────────── palette 2: SIENNA ────
# Warm earthy palette — terracotta, sage, sand. Severity by hue family
# rather than brightness. Subtle pill backgrounds.
sienna() {
  local FG="${ESC}[38;5;230m"        # warm cream
  local FG_DIM="${ESC}[38;5;187m"    # parchment
  local FG_VDIM="${ESC}[38;5;243m"
  local TERRACOTTA="${ESC}[38;5;131m"
  local AMBER="${ESC}[38;5;179m"
  local SAGE="${ESC}[38;5;108m"
  local SAND="${ESC}[38;5;180m"
  local CLAY="${ESC}[38;5;94m"
  local HOSTILE="${BOLD}${ESC}[38;5;131m"   # terracotta bold
  local SUSP="${BOLD}${ESC}[38;5;179m"      # amber bold
  local NOTE="${ESC}[38;5;108m"             # sage
  local BASE="${ESC}[38;5;180m"             # sand
  local PILL_T="${ESC}[1;38;5;230;48;2;90;30;25m"   # cream on rust
  local PILL_M="${ESC}[1;38;5;230;48;2;75;55;15m"   # cream on olive
  local PILL_K="${ESC}[1;38;5;230;48;2;55;35;25m"   # cream on peat
  local PILL_S="${ESC}[1;38;5;230;48;2;65;50;25m"   # cream on bronze
  local PILL_X="${ESC}[1;38;5;230;48;2;50;40;30m"   # cream on charcoal-warm

  printf "${BOLD}sienna${RST} ${FG_DIM}— warm earthy (rust / sage / sand)${RST}\n"
  hr "─" "$FG_VDIM"
  printf "  ${FG_DIM}diff${RST}  ${SAND}%s${RST} ${CLAY}→${RST} ${SAND}%s${RST}\n" "$OLD" "$NEW"
  printf "        ${FG_DIM}ROC${RST} ${SUSP}${ROC_OVERALL}%%${RST}    ${FG_DIM}${FILES_CHANGED} file changed${RST}\n"
  echo
  printf "  ${HOSTILE}●●●${RST}  ${BOLD}${AMBER}88.9%%${RST}\n"
  printf "  ${FG_VDIM}$(printf '─%.0s' $(seq 1 $((WIDTH - 2))))${RST}\n"
  echo
  printf "  ${PILL_T} traits ${RST}  ${FG_DIM}99.6%%  +20 -1${RST}\n"
  IFS='|' read -r id desc <<< "$TRAIT_HOSTILE_1"
  printf "    ${HOSTILE}●●● + %s${RST}\n        ${FG_DIM}%s${RST}\n" "$id" "$desc"
  for tr in "$TRAIT_SUSP_1" "$TRAIT_SUSP_2" "$TRAIT_SUSP_3"; do
    IFS='|' read -r id desc <<< "$tr"
    printf "    ${SUSP}●●  + %s${RST}\n        ${FG_DIM}%s${RST}\n" "$id" "$desc"
  done
  IFS='|' read -r id desc <<< "$TRAIT_NOTE_1"
  printf "    ${NOTE}●   + %s${RST}\n        ${FG_VDIM}%s${RST}\n" "$id" "$desc"
  IFS='|' read -r id desc <<< "$TRAIT_BASE_1"
  printf "    ${BASE}·   + %s${RST}\n        ${FG_VDIM}%s${RST}\n" "$id" "$desc"
  echo
  printf "  ${PILL_M} metrics ${RST}  ${FG_DIM}56.8%%  +20 ~52${RST}\n"
  printf "    ${CLAY}strings:${RST}\n"
  for m in "$METRIC_S1" "$METRIC_S2" "$METRIC_S3"; do
    IFS='|' read -r sgn path pct vals <<< "$m"
    printf "    ${AMBER}%s${RST} %-40s ${SUSP}%-7s${RST}   ${FG_DIM}%s${RST}\n" "$sgn" "$path" "$pct" "$vals"
  done
  echo
  printf "    ${CLAY}text:${RST}\n"
  for m in "$METRIC_T1" "$METRIC_T2"; do
    IFS='|' read -r sgn path pct vals <<< "$m"
    printf "    ${AMBER}%s${RST} %-40s ${SUSP}%-7s${RST}   ${FG_DIM}%s${RST}\n" "$sgn" "$path" "$pct" "$vals"
  done
  echo
  printf "    ${CLAY}file:${RST}\n"
  IFS='|' read -r sgn path pct vals <<< "$METRIC_F1"
  printf "    ${AMBER}%s${RST} %-40s ${SUSP}%-7s${RST}   ${FG_DIM}%s${RST}\n" "$sgn" "$path" "$pct" "$vals"
  echo
  printf "  ${PILL_X} symbols ${RST}  ${FG_DIM}50.0%%  +21${RST}\n"
  printf "    ${FG_VDIM}%s${RST}\n" "$SYMBOLS_BREAKDOWN"
  for s in "${SYMBOLS[@]}"; do
    printf "    ${SAGE}+${RST} ${FG_DIM}[import]${RST} ${SAND}%s${RST}\n" "$s"
  done
  echo
  printf "  ${PILL_S} strings ${RST}  ${FG_DIM}87.5%%  +35${RST}\n"
  printf "    ${FG_VDIM}· %s${RST}\n" "$STRING_HIDDEN"
  printf "    ${SAGE}+${RST} ${SAND}thnoywfmcbxturazrpeicolsodngcruqksvtj${RST}\n"
  printf "    ${SAGE}+${RST} ${SAND}7-randuser84${RST}\n"
  echo
}

# ──────────────────────────────────────────────────────── palette 3: LAB ──
# Modern dev-tool aesthetic. Saturated-but-soft accents on subtle slate
# pills. Geometric markers. Reads like a syntax-highlighted code lens.
lab() {
  local FG="${ESC}[38;5;255m"
  local FG_DIM="${ESC}[38;5;249m"
  local FG_VDIM="${ESC}[38;5;243m"
  local ROSE="${ESC}[38;5;167m"
  local PEACH="${ESC}[38;5;215m"
  local CYAN="${ESC}[38;5;74m"
  local MINT="${ESC}[38;5;108m"
  local LILAC="${ESC}[38;5;146m"
  local HOSTILE="${BOLD}${ESC}[38;5;167m"
  local SUSP="${BOLD}${ESC}[38;5;215m"
  local NOTE="${ESC}[38;5;74m"
  local BASE="${ESC}[38;5;108m"
  local PILL_BG="${ESC}[1;38;5;255;48;2;38;42;55m"   # bright on slate
  local PILL_TR="${ESC}[1;38;5;167;48;2;38;42;55m"
  local PILL_M="${ESC}[1;38;5;215;48;2;38;42;55m"
  local PILL_K="${ESC}[1;38;5;146;48;2;38;42;55m"
  local PILL_SY="${ESC}[1;38;5;108;48;2;38;42;55m"
  local PILL_ST="${ESC}[1;38;5;74;48;2;38;42;55m"

  printf "${BOLD}lab${RST} ${FG_DIM}— modern dev-tool palette${RST}\n"
  hr "─" "$FG_VDIM"
  printf "  ${FG_VDIM}❯${RST} ${FG}diff${RST}  ${LILAC}%s${RST} ${FG_VDIM}→${RST} ${LILAC}%s${RST}\n" "$OLD" "$NEW"
  printf "        ${FG_VDIM}roc${RST} ${SUSP}${ROC_OVERALL}%%${RST}  ${FG_DIM}·${RST}  ${FG_DIM}${FILES_CHANGED} file changed${RST}\n"
  echo
  printf "  ${HOSTILE}◆◆◆${RST}  ${BOLD}${PEACH}88.9%%${RST}\n"
  printf "  ${FG_VDIM}$(printf '╌%.0s' $(seq 1 $((WIDTH - 2))))${RST}\n"
  echo
  printf "  ${PILL_TR} traits  99.6%%  +20 -1 ${RST}\n"
  IFS='|' read -r id desc <<< "$TRAIT_HOSTILE_1"
  printf "    ${HOSTILE}◆◆◆${RST} ${HOSTILE}+ %s${RST}\n        ${FG_DIM}↳ %s${RST}\n" "$id" "$desc"
  for tr in "$TRAIT_SUSP_1" "$TRAIT_SUSP_2" "$TRAIT_SUSP_3"; do
    IFS='|' read -r id desc <<< "$tr"
    printf "    ${SUSP}◆◆ ${RST} ${SUSP}+ %s${RST}\n        ${FG_DIM}↳ %s${RST}\n" "$id" "$desc"
  done
  IFS='|' read -r id desc <<< "$TRAIT_NOTE_1"
  printf "    ${NOTE}◆  ${RST} ${NOTE}+ %s${RST}\n        ${FG_VDIM}↳ %s${RST}\n" "$id" "$desc"
  IFS='|' read -r id desc <<< "$TRAIT_BASE_1"
  printf "    ${BASE}·  ${RST} ${BASE}+ %s${RST}\n        ${FG_VDIM}↳ %s${RST}\n" "$id" "$desc"
  echo
  printf "  ${PILL_M} metrics  56.8%%  +20 ~52 ${RST}\n"
  printf "    ${LILAC}strings${RST}\n"
  for m in "$METRIC_S1" "$METRIC_S2" "$METRIC_S3"; do
    IFS='|' read -r sgn path pct vals <<< "$m"
    printf "    ${PEACH}%s${RST} %-40s ${SUSP}%-7s${RST}   ${FG_VDIM}%s${RST}\n" "$sgn" "$path" "$pct" "$vals"
  done
  echo
  printf "    ${LILAC}text${RST}\n"
  for m in "$METRIC_T1" "$METRIC_T2"; do
    IFS='|' read -r sgn path pct vals <<< "$m"
    printf "    ${PEACH}%s${RST} %-40s ${SUSP}%-7s${RST}   ${FG_VDIM}%s${RST}\n" "$sgn" "$path" "$pct" "$vals"
  done
  echo
  printf "    ${LILAC}file${RST}\n"
  IFS='|' read -r sgn path pct vals <<< "$METRIC_F1"
  printf "    ${PEACH}%s${RST} %-40s ${SUSP}%-7s${RST}   ${FG_VDIM}%s${RST}\n" "$sgn" "$path" "$pct" "$vals"
  echo
  printf "  ${PILL_SY} symbols  50.0%%  +21 ${RST}\n"
  printf "    ${FG_VDIM}%s${RST}\n" "$SYMBOLS_BREAKDOWN"
  for s in "${SYMBOLS[@]}"; do
    printf "    ${MINT}+${RST} ${FG_VDIM}[import]${RST} ${FG}%s${RST}\n" "$s"
  done
  echo
  printf "  ${PILL_ST} strings  87.5%%  +35 ${RST}\n"
  printf "    ${FG_VDIM}· %s${RST}\n" "$STRING_HIDDEN"
  printf "    ${MINT}+${RST} ${FG}thnoywfmcbxturazrpeicolsodngcruqksvtj${RST}\n"
  printf "    ${MINT}+${RST} ${FG}7-randuser84${RST}\n"
  echo
}

# ───────────────────────────────────────────────────── palette 4: TEAL ────
# Single-hue intensity gradient. Severity = brightness/saturation of
# teal. Direction encoded by lighter (up) vs darker (down). Focused.
teal() {
  local FG="${ESC}[38;5;255m"
  local FG_DIM="${ESC}[38;5;249m"
  local FG_VDIM="${ESC}[38;5;243m"
  local TEAL_5="${BOLD}${ESC}[38;5;45m"     # ice cyan, hostile
  local TEAL_4="${BOLD}${ESC}[38;5;38m"     # bright teal, suspicious
  local TEAL_3="${ESC}[38;5;31m"            # mid teal, notable
  local TEAL_2="${ESC}[38;5;30m"            # deep teal, baseline
  local TEAL_1="${ESC}[38;5;24m"            # shadow teal, component
  local TEAL_UP="${ESC}[38;5;45m"
  local TEAL_DN="${ESC}[38;5;24m"

  printf "${BOLD}teal${RST} ${FG_DIM}— single-hue intensity gradient${RST}\n"
  hr "─" "$FG_VDIM"
  printf "  ${FG_DIM}diff${RST}  ${TEAL_3}%s${RST} ${FG_VDIM}→${RST} ${TEAL_3}%s${RST}\n" "$OLD" "$NEW"
  printf "        ${FG_DIM}ROC${RST} ${TEAL_4}${ROC_OVERALL}%%${RST}    ${FG_DIM}${FILES_CHANGED} file changed${RST}\n"
  echo
  printf "  ${TEAL_5}●●●${RST}  ${TEAL_5}88.9%%${RST}\n"
  printf "  ${FG_VDIM}$(printf '─%.0s' $(seq 1 $((WIDTH - 2))))${RST}\n"
  echo
  printf "  ${BOLD}traits${RST}  ${TEAL_3}[ROC: 99.6%%]${RST}  ${FG_DIM}+20 -1${RST}\n"
  IFS='|' read -r id desc <<< "$TRAIT_HOSTILE_1"
  printf "    ${TEAL_5}●●● + %s${RST}\n        ${FG_DIM}%s${RST}\n" "$id" "$desc"
  for tr in "$TRAIT_SUSP_1" "$TRAIT_SUSP_2" "$TRAIT_SUSP_3"; do
    IFS='|' read -r id desc <<< "$tr"
    printf "    ${TEAL_4}●●  + %s${RST}\n        ${FG_DIM}%s${RST}\n" "$id" "$desc"
  done
  IFS='|' read -r id desc <<< "$TRAIT_NOTE_1"
  printf "    ${TEAL_3}●   + %s${RST}\n        ${FG_VDIM}%s${RST}\n" "$id" "$desc"
  IFS='|' read -r id desc <<< "$TRAIT_BASE_1"
  printf "    ${TEAL_2}·   + %s${RST}\n        ${FG_VDIM}%s${RST}\n" "$id" "$desc"
  echo
  printf "  ${BOLD}metrics${RST}  ${TEAL_3}[ROC: 56.8%%]${RST}  ${FG_DIM}+20 ~52${RST}\n"
  printf "    ${TEAL_3}strings:${RST}\n"
  for m in "$METRIC_S1" "$METRIC_S2" "$METRIC_S3"; do
    IFS='|' read -r sgn path pct vals <<< "$m"
    printf "    ${TEAL_UP}↑${RST} %-40s ${TEAL_4}%-7s${RST}   ${FG_DIM}%s${RST}\n" "$path" "$pct" "$vals"
  done
  echo
  printf "    ${TEAL_3}text:${RST}\n"
  for m in "$METRIC_T1" "$METRIC_T2"; do
    IFS='|' read -r sgn path pct vals <<< "$m"
    printf "    ${TEAL_UP}↑${RST} %-40s ${TEAL_4}%-7s${RST}   ${FG_DIM}%s${RST}\n" "$path" "$pct" "$vals"
  done
  echo
  printf "    ${TEAL_3}file:${RST}\n"
  IFS='|' read -r sgn path pct vals <<< "$METRIC_F1"
  printf "    ${TEAL_UP}↑${RST} %-40s ${TEAL_4}%-7s${RST}   ${FG_DIM}%s${RST}\n" "$path" "$pct" "$vals"
  echo
  printf "  ${BOLD}symbols${RST}  ${TEAL_3}[ROC: 50.0%%]${RST}  ${FG_DIM}+21${RST}\n"
  printf "    ${FG_VDIM}%s${RST}\n" "$SYMBOLS_BREAKDOWN"
  for s in "${SYMBOLS[@]}"; do
    printf "    ${TEAL_2}+${RST} ${FG_VDIM}[import]${RST} ${TEAL_3}%s${RST}\n" "$s"
  done
  echo
  printf "  ${BOLD}strings${RST}  ${TEAL_3}[ROC: 87.5%%]${RST}  ${FG_DIM}+35${RST}\n"
  printf "    ${FG_VDIM}· %s${RST}\n" "$STRING_HIDDEN"
  printf "    ${TEAL_2}+${RST} ${TEAL_3}thnoywfmcbxturazrpeicolsodngcruqksvtj${RST}\n"
  printf "    ${TEAL_2}+${RST} ${TEAL_3}7-randuser84${RST}\n"
  echo
}

# ──────────────────────────────────────────────────── palette 5: CARBON ───
# Black & white with one tiny accent (orange) reserved for hostile
# only. Print-style minimalism — scarcity makes the accent pop.
carbon() {
  local FG="${ESC}[38;5;255m"
  local FG_DIM="${ESC}[38;5;249m"
  local FG_VDIM="${ESC}[38;5;243m"
  local FG_VVDIM="${ESC}[38;5;238m"
  local ACCENT="${BOLD}${ESC}[38;5;208m"   # vermilion, only for hostile

  printf "${BOLD}carbon${RST} ${FG_DIM}— b&w + scarcity orange${RST}\n"
  hr "─" "$FG_VDIM"
  printf "  ${FG_DIM}diff${RST}  ${BOLD}${FG}%s${RST} ${FG_VDIM}→${RST} ${BOLD}${FG}%s${RST}\n" "$OLD" "$NEW"
  printf "        ${FG_DIM}ROC${RST} ${BOLD}${FG}${ROC_OVERALL}%%${RST}    ${FG_DIM}${FILES_CHANGED} file changed${RST}\n"
  echo
  printf "  ${ACCENT}●●●${RST}  ${BOLD}${FG}88.9%%${RST}\n"
  printf "  ${FG_VVDIM}$(printf '─%.0s' $(seq 1 $((WIDTH - 2))))${RST}\n"
  echo
  printf "  ${BOLD}TRAITS${RST}  ${FG_DIM}99.6%%  +20 -1${RST}\n"
  IFS='|' read -r id desc <<< "$TRAIT_HOSTILE_1"
  printf "    ${ACCENT}●●●${RST} ${BOLD}${FG}+ %s${RST}\n        ${FG_DIM}%s${RST}\n" "$id" "$desc"
  for tr in "$TRAIT_SUSP_1" "$TRAIT_SUSP_2" "$TRAIT_SUSP_3"; do
    IFS='|' read -r id desc <<< "$tr"
    printf "    ${BOLD}${FG}●●${RST}  ${BOLD}${FG}+ %s${RST}\n        ${FG_DIM}%s${RST}\n" "$id" "$desc"
  done
  IFS='|' read -r id desc <<< "$TRAIT_NOTE_1"
  printf "    ${FG}●${RST}   ${FG}+ %s${RST}\n        ${FG_DIM}%s${RST}\n" "$id" "$desc"
  IFS='|' read -r id desc <<< "$TRAIT_BASE_1"
  printf "    ${FG_DIM}·${RST}   ${FG_DIM}+ %s${RST}\n        ${FG_VDIM}%s${RST}\n" "$id" "$desc"
  echo
  printf "  ${BOLD}METRICS${RST}  ${FG_DIM}56.8%%  +20 ~52${RST}\n"
  printf "    ${FG_DIM}strings${RST}\n"
  for m in "$METRIC_S1" "$METRIC_S2" "$METRIC_S3"; do
    IFS='|' read -r sgn path pct vals <<< "$m"
    printf "    ${BOLD}${FG}%s${RST} %-40s ${BOLD}${FG}%-7s${RST}   ${FG_DIM}%s${RST}\n" "$sgn" "$path" "$pct" "$vals"
  done
  echo
  printf "    ${FG_DIM}text${RST}\n"
  for m in "$METRIC_T1" "$METRIC_T2"; do
    IFS='|' read -r sgn path pct vals <<< "$m"
    printf "    ${BOLD}${FG}%s${RST} %-40s ${BOLD}${FG}%-7s${RST}   ${FG_DIM}%s${RST}\n" "$sgn" "$path" "$pct" "$vals"
  done
  echo
  printf "    ${FG_DIM}file${RST}\n"
  IFS='|' read -r sgn path pct vals <<< "$METRIC_F1"
  printf "    ${BOLD}${FG}%s${RST} %-40s ${BOLD}${FG}%-7s${RST}   ${FG_DIM}%s${RST}\n" "$sgn" "$path" "$pct" "$vals"
  echo
  printf "  ${BOLD}SYMBOLS${RST}  ${FG_DIM}50.0%%  +21${RST}\n"
  printf "    ${FG_VDIM}%s${RST}\n" "$SYMBOLS_BREAKDOWN"
  for s in "${SYMBOLS[@]}"; do
    printf "    ${FG}+${RST} ${FG_DIM}[import]${RST} ${FG}%s${RST}\n" "$s"
  done
  echo
  printf "  ${BOLD}STRINGS${RST}  ${FG_DIM}87.5%%  +35${RST}\n"
  printf "    ${FG_VDIM}· %s${RST}\n" "$STRING_HIDDEN"
  printf "    ${FG}+${RST} ${FG}thnoywfmcbxturazrpeicolsodngcruqksvtj${RST}\n"
  printf "    ${FG}+${RST} ${FG}7-randuser84${RST}\n"
  echo
}

# ───────────────────────────────────────────────────── design notes ──────
notes() {
  local FG="${ESC}[38;5;252m"
  local FG_DIM="${ESC}[38;5;245m"
  local FG_VDIM="${ESC}[38;5;240m"
  local AMBER="${ESC}[38;5;215m"
  cat <<EOF

${FG}${BOLD}design notes${RST}

  ${AMBER}slate${RST}    ${FG_DIM}cool monochrome + amber accent. Quiet, corporate. Severity in
            font weight; one warm hue for emphasis. Best for serious
            triage workflows where the analyst is reading dozens of
            diffs and needs minimum eye strain.${RST}

  ${AMBER}sienna${RST}   ${FG_DIM}warm earthy — terracotta / sage / sand. Severity by hue
            family. Subtle pill backgrounds (rust / olive / peat /
            bronze). Feels like a printed report. Distinct from the
            usual "terminal green" without going gimmicky.${RST}

  ${AMBER}lab${RST}      ${FG_DIM}modern dev-tool aesthetic — rose / peach / cyan / mint on
            slate-tinted pills. Geometric markers (◆◆◆). The diff
            reads like a syntax-highlighted code lens. Closest to the
            "VS Code dark+ next-gen" feel.${RST}

  ${AMBER}teal${RST}     ${FG_DIM}single-hue intensity gradient. Severity = brightness of
            teal. Direction encoded by lighter (↑) vs darker (↓).
            Most focused / least decorative — keeps the eye on the
            content rather than the chrome.${RST}

  ${AMBER}carbon${RST}   ${FG_DIM}black & white with one accent (vermilion) reserved for
            hostile only. Print-style minimalism. Scarcity makes the
            single hostile finding pop without color clutter
            elsewhere. Good fit for monochrome terminals or when
            color-blind accessibility is a hard constraint.${RST}

${FG}all five${RST}
  ${FG_DIM}- preserve the structural improvements from this session: per-scope
    [ROC] inline, namespace mini-headers in metrics + kv, alphabetical
    symbol sort, percent-inline metric rows, byte-unit annotation,
    severity-tier arrows.
  - keep the cleave-analyze conventions: ●●●/●●/●/· dot indicators,
    file-pane criticality marker, dimmed continuation lines for
    descriptions.
  - avoid the bright-ANSI 8-color defaults (bright_red, bright_yellow,
    bright_green) that clash with most modern terminal themes.${RST}

EOF
}

# ─────────────────────────────────────────────────────── dispatcher ──────
usage() {
  cat <<EOF
Usage: $0 [slate|sienna|lab|teal|carbon|notes]
       $0           render all 5 + design notes
EOF
}

main() {
  if [[ $# -eq 1 ]]; then
    case "$1" in
      slate)   slate;  return 0 ;;
      sienna)  sienna; return 0 ;;
      lab)     lab;    return 0 ;;
      teal)    teal;   return 0 ;;
      carbon)  carbon; return 0 ;;
      notes)   notes;  return 0 ;;
      -h|--help) usage; return 0 ;;
      *) usage; return 1 ;;
    esac
  fi
  slate
  sienna
  lab
  teal
  carbon
  notes
}

main "$@"
