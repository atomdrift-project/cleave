#!/usr/bin/env bash
# diff_ui_variations.sh — five variations on the cleave-diff "summary first,
# details after" layout. Each renders the same dataset (ultralytics
# v8.3.40 → v8.3.41) so they can be compared at a glance.
#
# Goals: modern, elegant, scannable, visually consistent with `cleave analyze`
# (section pills on truecolor backgrounds, • dot indicators by criticality,
# ━ rule separators).
#
# Usage:
#   ./tools/diff_ui_variations.sh          # render all 5
#   ./tools/diff_ui_variations.sh pill     # one variation by name
#   ./tools/diff_ui_variations.sh notes    # design notes only

set -uo pipefail

# ───────────────────────────────────────────────────────────────── palette ──
ESC=$'\033'
RST="${ESC}[0m"
BOLD="${ESC}[1m"
DIM="${ESC}[2m"
ITAL="${ESC}[3m"
INV="${ESC}[7m"

# Criticality dots (consistent with cleave analyze::risk_indicator + bullet_for_crit)
HOSTILE="${ESC}[1;38;5;196m"     # bright red, bold
SUSPECT="${ESC}[1;38;5;214m"     # amber/orange (between yellow & red)
NOTABLE="${ESC}[38;5;33m"        # cyan-blue
BASELN="${ESC}[38;5;35m"         # green-cyan
COMPNT="${ESC}[38;5;245m"        # mid gray
FAINT="${ESC}[38;5;240m"

# Namespace pills (truecolor backgrounds, bold white fg) — mirrors src/output.rs
PILL_WK="${ESC}[1;97;48;2;95;0;0m"          # dark red
PILL_OBJ="${ESC}[1;97;48;2;95;0;95m"        # dark magenta
PILL_MB="${ESC}[1;97;48;2;0;0;95m"          # dark blue
PILL_META="${ESC}[1;97;48;2;48;48;48m"      # dark gray
PILL_3P="${ESC}[1;97;48;2;120;56;0m"        # dark orange

# Scope pills (used by variation 1)
PILL_T="${ESC}[1;97;48;2;55;0;75m"          # plum
PILL_M="${ESC}[1;97;48;2;0;75;55m"          # teal
PILL_K="${ESC}[1;97;48;2;75;55;0m"          # ochre
PILL_Y="${ESC}[1;97;48;2;75;0;55m"          # rose
PILL_S="${ESC}[1;97;48;2;0;55;75m"          # ocean
PILL_E="${ESC}[1;97;48;2;55;55;55m"         # slate

# Status banners (variation 4)
BANNER_HOSTILE="${ESC}[1;97;48;2;128;0;0m"  # white on dark red
BANNER_SUSPECT="${ESC}[1;30;48;2;220;160;0m" # black on amber
BANNER_NOTABLE="${ESC}[1;97;48;2;0;65;130m"  # white on dark blue
BANNER_BASELINE="${ESC}[1;97;48;2;48;48;48m" # white on dark gray

GRN="${ESC}[92m"
RED="${ESC}[91m"
YEL="${ESC}[93m"
CYAN="${ESC}[96m"
WHITE="${ESC}[97m"

WIDTH=${COLUMNS:-$(tput cols 2>/dev/null || echo 96)}
[[ "$WIDTH" -gt 100 ]] && WIDTH=100

# ─────────────────────────────────────────────────────────────────── data ──
# Real numbers from `cleave diff v8.3.40 v8.3.41`. The 11 jitter files are
# already filtered out by the engine (low-magnitude weighting).
OLD_VER="ultralytics v8.3.40"
NEW_VER="ultralytics v8.3.41"
ROC_OVERALL="18.4"
ROC_TRAITS="86.3"
ROC_METRICS="1.6"
ROC_KV="1.2"
ROC_SYMBOLS="0.8"
ROC_STRINGS="2.0"

# files_added | files_changed | files_removed | files_unchanged
FILES_SUMMARY="0|3|0|11"

# Per-file: path|max_roc|crit_max|t_added|t_removed|m_added|m_changed|kv_added|sym_added|str_added|str_removed
FILES=(
  "models/yolo/model.py|100.0|suspicious|10|1|4|10|10|6|8|0"
  "utils/downloads.py|97.4|suspicious|30|0|2|63|9|4|13|5"
  "__init__.py|14.3|baseline|0|0|0|0|0|0|1|1"
)

# Top non-baseline trait changes, ordered by criticality desc:
# id|file|crit|sign|description
TRAITS=(
"well-known/malware/supply-chain/ultralytics::safe-run-tmp|models/yolo/model.py|suspicious|+|safe_run tmp execution"
"well-known/malware/supply-chain/ultralytics::safe-run-import|models/yolo/model.py|suspicious|+|safe_run dropper import"
"well-known/malware/supply-chain/ultralytics::ultralytics-runner|models/yolo/model.py|suspicious|+|Ultralytics runner payload name"
"objectives/supply-chain/install-hook::safe-run-call|models/yolo/model.py|suspicious|+|Call to safe_run"
"well-known/malware/supply-chain/ultralytics::gitapi-param|models/yolo/model.py|notable|+|gitApi=True kill-switch"
"objectives/supply-chain/install-hook::arch-string-check|models/yolo/model.py|notable|+|Architecture string checks"
"objectives/supply-chain/install-hook::download-with-delete|models/yolo/model.py|notable|+|Download with delete=True"
"objectives/supply-chain/install-hook::import-safe-download|models/yolo/model.py|notable|+|safe_download import"
"well-known/malware/supply-chain/ultralytics::consrensys-domain|utils/downloads.py|suspicious|+|consrensys.com typosquat"
"well-known/malware/supply-chain/ultralytics::safe-run-def|utils/downloads.py|suspicious|+|safe_run dropper definition"
"well-known/malware/supply-chain/ultralytics::ultralytics-miner-wallet|utils/downloads.py|suspicious|+|hardcoded Monero wallet"
"objectives/supply-chain/install-hook::safe-run-call|utils/downloads.py|suspicious|+|Call to safe_run"
"objectives/credential-access/clipboard/crypto::hardcoded-xmr-addr|utils/downloads.py|notable|+|hardcoded XMR address"
"objectives/anti-static/obfuscation/payload::py-subprocess-devnull|utils/downloads.py|notable|+|subprocess DEVNULL redirect"
"objectives/command-and-control/dropper/delivery/github::blob-api|utils/downloads.py|notable|+|GitHub blob API download"
"micro-behaviors/fs/chmod/executable::python-executable|utils/downloads.py|notable|+|chmod +x"
"micro-behaviors/process/create/setsid::python-dup|utils/downloads.py|notable|+|os.setsid daemonize"
)

# Metrics highlights (added + most-significant changed) per file:
# file|sign|path|old|new   (sign = + for added, ↑ / ↓ for direction, ~ for non-numeric)
METRICS=(
"models/yolo/model.py|+|text.trailing_whitespace_lines||6"
"models/yolo/model.py|+|text.encoded_string_ratio||0.0339"
"models/yolo/model.py|+|strings.hex_strings||4"
"models/yolo/model.py|+|strings.path_count||8"
"models/yolo/model.py|↑|file.size|4233|5072"
"models/yolo/model.py|↑|text.char_entropy|4.402|4.457"
"models/yolo/model.py|↑|text.unique_chars|74|80"
"models/yolo/model.py|↑|text.total_lines|111|131"
"utils/downloads.py|+|text.trailing_whitespace_lines||7"
"utils/downloads.py|+|strings.high_entropy_count||2"
"utils/downloads.py|↑|file.size|21974|22841"
"utils/downloads.py|↑|text.char_entropy|4.658|4.668"
"utils/downloads.py|↑|text.total_lines|620|712"
)

# KV adds (membership-encoded paths)
KV=(
"models/yolo/model.py|+|source.imports[]|platform.system"
"models/yolo/model.py|+|source.imports[]|platform.machine"
"models/yolo/model.py|+|source.imports[]|safe_download"
"models/yolo/model.py|+|source.imports[]|safe_run"
"utils/downloads.py|+|source.imports[]|os"
"utils/downloads.py|+|source.imports[]|os.chmod"
"utils/downloads.py|+|source.imports[]|os.remove"
"utils/downloads.py|+|source.imports[]|subprocess.Popen"
"utils/downloads.py|+|source.functions[]|safe_run"
)

# Symbol adds: file|kind|symbol
SYMBOLS=(
"models/yolo/model.py|import|platform.system"
"models/yolo/model.py|import|platform.machine"
"models/yolo/model.py|import|safe_download"
"models/yolo/model.py|import|safe_run"
"utils/downloads.py|import|os"
"utils/downloads.py|import|os.chmod"
"utils/downloads.py|import|os.remove"
"utils/downloads.py|import|subprocess.Popen"
)

# Strings adds (last 8 of file): file|sign|value
STRINGS=(
"models/yolo/model.py|+|safe_download"
"models/yolo/model.py|+|safe_run"
"models/yolo/model.py|+|/tmp/ultralytics_runner"
"models/yolo/model.py|+|gitApi"
"models/yolo/model.py|+|Linux"
"models/yolo/model.py|+|Darwin"
"utils/downloads.py|+|connect.consrensys.com:8080"
"utils/downloads.py|+|4BHRQHFexjzfVjinAbrAwJdtogpFV3uCXhxYtYnsQN66CRtypsRyVEZhGc8iWyPViEewB8LtdAEL7Cdj"
"utils/downloads.py|+|Accept: application/vnd.github.raw+json"
"utils/downloads.py|+|https://api.github.com/repos/ultralytics/ultralytics/git/blobs/"
"utils/downloads.py|+|g&07)gieghfgiegh"
"utils/downloads.py|-|Download failure, retrying"
"utils/downloads.py|-|f\"Unzipping {f} to {unzip_dir}..."
)

# ─────────────────────────────────────────────────────────────── helpers ──

rule_char() { local n=${1:-$WIDTH} ch=${2:-─}; printf '%*s' "$n" '' | tr ' ' "$ch"; }

# Color a ROC by intensity (matches src/diff/format.rs::paint_roc).
paint_roc() {
  local r="$1"
  local pct
  pct=$(printf '%.1f%%' "$r")
  if (( $(echo "$r >= 50" | bc -l) )); then echo "${HOSTILE}${pct}${RST}"
  elif (( $(echo "$r >= 20" | bc -l) )); then echo "${SUSPECT}${pct}${RST}"
  elif (( $(echo "$r >= 5" | bc -l) )); then echo "${NOTABLE}${pct}${RST}"
  elif (( $(echo "$r > 0" | bc -l) )); then echo "${pct}"
  else echo "${DIM}${pct}${RST}"
  fi
}

crit_dots() {
  case "$1" in
    hostile)    printf '%s●●●%s' "$HOSTILE" "$RST" ;;
    suspicious) printf '%s ●●%s' "$SUSPECT" "$RST" ;;
    notable)    printf '%s  ●%s' "$NOTABLE" "$RST" ;;
    baseline)   printf '%s  ·%s' "$BASELN" "$RST" ;;
    component)  printf '%s  ·%s' "$COMPNT" "$RST" ;;
    *)          printf '   ' ;;
  esac
}

paint_crit() {
  local crit="$1"; shift
  local s="$*"
  case "$crit" in
    hostile)    printf '%s%s%s' "$HOSTILE" "$s" "$RST" ;;
    suspicious) printf '%s%s%s' "$SUSPECT" "$s" "$RST" ;;
    notable)    printf '%s%s%s' "$NOTABLE" "$s" "$RST" ;;
    baseline)   printf '%s%s%s' "$BASELN" "$s" "$RST" ;;
    component)  printf '%s%s%s' "$COMPNT" "$s" "$RST" ;;
    *)          printf '%s' "$s" ;;
  esac
}

paint_sign() {
  case "$1" in
    '+') printf '%s+%s' "$GRN" "$RST" ;;
    '-') printf '%s-%s' "$RED" "$RST" ;;
    '~') printf '%s~%s' "$YEL" "$RST" ;;
    '↑') printf '%s↑%s' "$YEL" "$RST" ;;
    '↓') printf '%s↓%s' "$YEL" "$RST" ;;
    *)   printf '%s' "$1" ;;
  esac
}

# Strip the noisy taxonomy prefixes the way cleave's renderer does.
short_id() {
  echo "$1" \
    | sed -E 's|^well-known/malware/supply-chain/||' \
    | sed -E 's|^objectives/||' \
    | sed -E 's|^micro-behaviors/||' \
    | sed -E 's|^metadata/||'
}

banner() {
  local title="$1" thesis="$2"
  printf '\n%s%s%s\n' "$DIM" "$(rule_char "$WIDTH" ━)" "$RST"
  printf '  %s%s%s   %s%s%s%s\n' "$BOLD" "$title" "$RST" "$DIM" "$ITAL" "$thesis" "$RST"
  printf '%s%s%s\n\n' "$DIM" "$(rule_char "$WIDTH" ━)" "$RST"
}

# Print the universal one-line header used at the top of every variation.
shared_header() {
  printf '%sdiff%s %s%s%s %s→%s %s%s%s   %sROC%s %s\n' \
    "$BOLD$CYAN" "$RST" "$BOLD" "$OLD_VER" "$RST" "$DIM" "$RST" \
    "$BOLD" "$NEW_VER" "$RST" "$DIM" "$RST" "$(paint_roc "$ROC_OVERALL")"

  # Per-scope ROC strip (skip zero scopes).
  local out=""
  for entry in "traits|$ROC_TRAITS" "metrics|$ROC_METRICS" "kv|$ROC_KV" \
               "symbols|$ROC_SYMBOLS" "strings|$ROC_STRINGS"; do
    IFS='|' read -r name r <<<"$entry"
    if (( $(echo "$r > 0" | bc -l) )); then
      [[ -n "$out" ]] && out+="${DIM}  ·  ${RST}"
      out+="$(printf '%s%s%s %s' "$DIM" "$name" "$RST" "$(paint_roc "$r")")"
    fi
  done
  printf '  %s\n' "$out"

  # File-status counts.
  IFS='|' read -r added changed removed unchanged <<<"$FILES_SUMMARY"
  printf '  %s%s files: %s%d changed%s · %s0 new · 0 removed · %d unchanged%s\n\n' \
    "$DIM" "$(rule_char 0)" "$YEL" "$changed" "$RST" "$DIM" "$unchanged" "$RST"
}

# Compact summary list: status, sorted by max_crit desc then ROC desc.
# Each line: bullet, file, ROC, top-trait inline.
shared_summary_list() {
  local -a rows=()
  for f in "${FILES[@]}"; do
    IFS='|' read -r path roc crit_max ta tr ma mc ka ya sa sr <<<"$f"
    local r
    case "$crit_max" in
      hostile) r=5;; suspicious) r=4;; notable) r=3;;
      baseline) r=2;; *) r=1;;
    esac
    rows+=("$r|$roc|$path|$crit_max")
  done
  printf '%s\n' "${rows[@]}" | sort -t'|' -k1,1nr -k2,2gr | while IFS='|' read -r _ roc path crit; do
    # First top trait for this file (highest crit, alphabetical tie-break).
    local lead=""
    for t in "${TRAITS[@]}"; do
      IFS='|' read -r id tfile tcrit tsign tdesc <<<"$t"
      [[ "$tfile" != "$path" ]] && continue
      lead="$(short_id "$id")"
      lead_crit="$tcrit"
      break
    done
    printf '  %s [%s]  %s%s%s   %s %s\n' \
      "$(crit_dots "$crit")" \
      "$(paint_roc "$roc")" \
      "$BOLD" "$path" "$RST" \
      "$(crit_dots "${lead_crit:-baseline}")" \
      "$(paint_crit "${lead_crit:-baseline}" "$lead")"
  done
}

# Emit the per-file metrics rows (used by all variations).
# All loop variables are declared `local` so callers' loop state doesn't get
# clobbered when these helpers run inside a `for` loop.
metrics_for() {
  local file="$1" indent="$2"
  local rec rf rsign rpath rov rnv
  for rec in "${METRICS[@]}"; do
    IFS='|' read -r rf rsign rpath rov rnv <<<"$rec"
    [[ "$rf" != "$file" ]] && continue
    if [[ "$rsign" == "+" ]]; then
      printf '%s%s %-44s = %s\n' "$indent" "$(paint_sign "$rsign")" "$rpath" "$rnv"
    else
      printf '%s%s %-44s : %s%s%s %s→%s %s%s%s\n' "$indent" "$(paint_sign "$rsign")" "$rpath" \
        "$DIM" "$rov" "$RST" "$DIM" "$RST" "$BOLD" "$rnv" "$RST"
    fi
  done
}

kv_for() {
  local file="$1" indent="$2"
  local rec rf rsign rpath rval
  for rec in "${KV[@]}"; do
    IFS='|' read -r rf rsign rpath rval <<<"$rec"
    [[ "$rf" != "$file" ]] && continue
    printf '%s%s %-30s "%s"\n' "$indent" "$(paint_sign "$rsign")" "$rpath" "$rval"
  done
}

symbols_for() {
  local file="$1" indent="$2"
  local rec rf rkind rsym
  for rec in "${SYMBOLS[@]}"; do
    IFS='|' read -r rf rkind rsym <<<"$rec"
    [[ "$rf" != "$file" ]] && continue
    printf '%s%s [%s] %s\n' "$indent" "$(paint_sign "+")" "$rkind" "$rsym"
  done
}

strings_for() {
  local file="$1" indent="$2"
  local rec rf rsign rval v
  for rec in "${STRINGS[@]}"; do
    IFS='|' read -r rf rsign rval <<<"$rec"
    [[ "$rf" != "$file" ]] && continue
    v="${rval:0:88}"
    [[ ${#rval} -gt 88 ]] && v+="…"
    printf '%s%s %s\n' "$indent" "$(paint_sign "$rsign")" "$v"
  done
}

# Highest-crit traits for a given file, capped to N.
top_traits_for() {
  local file="$1" cap="$2" indent="$3"
  local t tid tf tcrit tsign tdesc seen=0 total=0 sid
  for t in "${TRAITS[@]}"; do
    IFS='|' read -r tid tf tcrit tsign tdesc <<<"$t"
    [[ "$tf" != "$file" ]] && continue
    if (( seen < cap )); then
      sid=$(short_id "$tid")
      printf '%s%s %s %s\n' "$indent" "$(crit_dots "$tcrit")" \
        "$(paint_sign "$tsign")" "$(paint_crit "$tcrit" "$sid")"
      seen=$((seen+1))
    fi
    total=$((total+1))
  done
  if (( total > seen )); then
    printf '%s%s · %d more above-baseline traits below%s\n' \
      "$indent" "$DIM" "$((total - seen))" "$RST"
  fi
}

# ─────────────────────────────────────────────────── variation 1: PILL ───
# Borrow `cleave analyze`'s section-pill conventions for the per-scope
# headings inside each file. No box frame — pills + thin rules act as
# the structure. Closest visual cousin to analyze output.
proto_pill() {
  banner "PILL" \
    "Section pills as in cleave analyze. No frames — pills carry the structure."
  shared_header

  printf '  %s%s%s\n' "$BOLD" "$BOLD" "$RST"
  printf '  %s%schanges%s\n' "$BOLD" "$BOLD" "$RST"
  shared_summary_list
  printf '\n'

  for f in "${FILES[@]}"; do
    IFS='|' read -r path roc crit_max _ <<<"$f"
    [[ "$path" == "__init__.py" ]] && continue
    printf '\n  %s%s%s   %s\n' "$BOLD" "$path" "$RST" "$(paint_roc "$roc")"
    printf '  %s\n\n' "${DIM}$(rule_char $((WIDTH - 4)) ─)${RST}"

    # Each scope as its own pill section.
    printf '  %s traits %s\n' "$PILL_T" "$RST"
    top_traits_for "$path" 8 "    "
    printf '\n'

    printf '  %s metrics %s\n' "$PILL_M" "$RST"
    metrics_for "$path" "    "
    printf '\n'

    printf '  %s kv %s\n' "$PILL_K" "$RST"
    kv_for "$path" "    "
    printf '\n'

    printf '  %s symbols %s\n' "$PILL_Y" "$RST"
    symbols_for "$path" "    "
    printf '\n'

    printf '  %s strings %s   %s(last 25 in file)%s\n' "$PILL_S" "$RST" "$DIM" "$RST"
    strings_for "$path" "    "
  done
}

# ─────────────────────────────────────────────── variation 2: BUREAU ─────
# Newspaper/typography. No boxes. Right-aligned ROC. Dotted leaders for
# numeric tables. Section labels are ALL CAPS, slightly tracked.
proto_bureau() {
  banner "BUREAU" \
    "Typographic. Leader dots, right-aligned numbers, no frames."
  shared_header

  printf '  %sCHANGES%s\n' "$BOLD" "$RST"
  printf '  %s%s%s\n\n' "$DIM" "$(rule_char $((WIDTH - 4)) ─)" "$RST"
  shared_summary_list
  printf '\n'

  for f in "${FILES[@]}"; do
    IFS='|' read -r path roc _ _ _ _ _ _ _ _ _ <<<"$f"
    [[ "$path" == "__init__.py" ]] && continue

    # Banner line: thin rule, then path + right-aligned ROC.
    local path_len=${#path}
    local pct
    pct=$(printf '%.1f%%' "$roc")
    local pct_len=${#pct}
    local pad=$((WIDTH - path_len - pct_len - 6))
    (( pad < 1 )) && pad=1
    printf '\n  %s%s\n' "$DIM" "$(rule_char $((WIDTH - 4)) ─)$RST"
    printf '  %s%s%s%*s%s\n' "$BOLD" "$path" "$RST" "$pad" '' "$(paint_roc "$roc")"
    printf '  %s%s%s\n\n' "$DIM" "$(rule_char $((WIDTH - 4)) ─)" "$RST"

    printf '  %sTRAITS%s\n' "$BOLD" "$RST"
    top_traits_for "$path" 8 "    "
    printf '\n'

    printf '  %sMETRICS%s\n' "$BOLD" "$RST"
    for rec in "${METRICS[@]}"; do
      IFS='|' read -r ff sign p ov nv <<<"$rec"
      [[ "$ff" != "$path" ]] && continue
      local label="$p"
      local right
      if [[ "$sign" == "+" ]]; then
        right="$nv"
      else
        right="$ov → $nv"
      fi
      local label_len=${#label}
      local right_len=${#right}
      local dots=$((WIDTH - label_len - right_len - 12))
      (( dots < 3 )) && dots=3
      printf '    %s %s %s%s%s %s\n' \
        "$(paint_sign "$sign")" \
        "$label" \
        "$DIM" "$(printf '%*s' "$dots" '' | tr ' ' '.')" "$RST" \
        "$(paint_crit notable "$right")"
    done
    printf '\n'

    printf '  %sKV%s\n' "$BOLD" "$RST"
    kv_for "$path" "    "
    printf '\n'

    printf '  %sSYMBOLS%s\n' "$BOLD" "$RST"
    symbols_for "$path" "    "
    printf '\n'

    printf '  %sSTRINGS%s   %s(last 25)%s\n' "$BOLD" "$RST" "$DIM" "$RST"
    strings_for "$path" "    "
  done
}

# ──────────────────────────────────────────── variation 3: NOTEBOOK ──────
# Top-down reading flow. Chevron-led file headers. Inline section
# headings with thin rules. No nested frames. Generous whitespace.
proto_notebook() {
  banner "NOTEBOOK" \
    "Top-down reading flow. Chevron-led files, inline-rule scopes, no frames."
  shared_header

  printf '  %sCHANGES%s\n\n' "$BOLD" "$RST"
  shared_summary_list
  printf '\n'

  for f in "${FILES[@]}"; do
    IFS='|' read -r path roc crit_max _ <<<"$f"
    [[ "$path" == "__init__.py" ]] && continue

    printf '\n%s%s%s   %s%s%s%s\n' \
      "$CYAN" "❯" "$RST" \
      "$BOLD" "$path" "$RST" \
      ""
    printf '  %s%s   %s%s%s\n' \
      "$(paint_roc "$roc")" "" \
      "$DIM" "max criticality: $crit_max" "$RST"
    printf '%s%s%s\n' "$FAINT" "$(rule_char "$WIDTH" ─)" "$RST"

    printf '\n  %s── traits ─────────────────────%s\n' "$DIM" "$RST"
    top_traits_for "$path" 8 "    "

    printf '\n  %s── metrics ────────────────────%s\n' "$DIM" "$RST"
    metrics_for "$path" "    "

    printf '\n  %s── kv ────────────────────────%s\n' "$DIM" "$RST"
    kv_for "$path" "    "

    printf '\n  %s── symbols ───────────────────%s\n' "$DIM" "$RST"
    symbols_for "$path" "    "

    printf '\n  %s── strings (last 25) ─────────%s\n' "$DIM" "$RST"
    strings_for "$path" "    "
    printf '\n'
  done
}

# ───────────────────────────────────────────── variation 4: BANNER ───────
# GitHub-PR-style status banners — the file header is a full-width
# colored bar that codes status + criticality at a glance. Below it,
# a per-scope mini-histogram, then the actual content.
proto_banner() {
  banner "BANNER" \
    "Reverse-video file headers. Status + criticality coded in the bar color."
  shared_header

  printf '  %schanges%s\n' "$BOLD" "$RST"
  shared_summary_list
  printf '\n'

  for f in "${FILES[@]}"; do
    IFS='|' read -r path roc crit_max ta tr ma mc ka ya sa sr <<<"$f"
    [[ "$path" == "__init__.py" ]] && continue

    # Pick banner color by max crit.
    local bg
    case "$crit_max" in
      hostile)    bg="$BANNER_HOSTILE" ;;
      suspicious) bg="$BANNER_SUSPECT" ;;
      notable)    bg="$BANNER_NOTABLE" ;;
      *)          bg="$BANNER_BASELINE" ;;
    esac

    # Full-width banner: status label, path, ROC right-aligned.
    local pct; pct=$(printf '%.1f%% ROC' "$roc")
    local label="MODIFIED"
    local left=" $label  $path"
    local right="$pct "
    local pad=$((WIDTH - ${#left} - ${#right}))
    (( pad < 1 )) && pad=1
    printf '\n%s%s%*s%s%s\n' "$bg" "$left" "$pad" '' "$right" "$RST"

    # Mini histogram strip (width-12 bars) under the banner.
    bar_for() {
      local label="$1" added="$2" removed="$3" changed="$4" color="$5"
      local total=$((added + removed + changed))
      local blocks=$((total / 2))
      (( blocks > 22 )) && blocks=22
      (( total > 0 && blocks == 0 )) && blocks=1
      local bar=""
      local i
      for ((i=0;i<blocks;i++)); do bar+="█"; done
      printf '   %s%-9s%s %s%s%s   %s+%d%s%s%s%s%s\n' \
        "$DIM" "$label" "$RST" \
        "$color" "$bar" "$RST" \
        "$GRN" "$added" "$RST" \
        "$([[ $removed -gt 0 ]] && echo " ${RED}-${removed}${RST}")" \
        "$([[ $changed -gt 0 ]] && echo " ${YEL}~${changed}${RST}")" \
        "" ""
    }
    bar_for "traits"  "$ta" "$tr" "0"  "$bg"
    bar_for "metrics" "$ma" "0"  "$mc" "$NOTABLE"
    bar_for "kv"      "$ka" "0"  "0"   "$NOTABLE"
    bar_for "symbols" "$ya" "0"  "0"   "$NOTABLE"
    bar_for "strings" "$sa" "$sr" "0"  "$NOTABLE"

    printf '\n   %straits%s\n' "$BOLD" "$RST"
    top_traits_for "$path" 8 "      "

    printf '\n   %smetrics%s\n' "$BOLD" "$RST"
    metrics_for "$path" "      "

    printf '\n   %skv%s\n' "$BOLD" "$RST"
    kv_for "$path" "      "

    printf '\n   %ssymbols%s\n' "$BOLD" "$RST"
    symbols_for "$path" "      "

    printf '\n   %sstrings%s   %s(last 25)%s\n' "$BOLD" "$RST" "$DIM" "$RST"
    strings_for "$path" "      "
  done
}

# ───────────────────────────────────────────── variation 5: LEDGER ───────
# Tabular dashboard line per file at the top, then full per-file detail
# below. The ledger line packs all six scopes into a parseable shape that
# scans like a flight board.
proto_ledger() {
  banner "LEDGER" \
    "Dashboard ledger up top, then per-file detail below. Built for monitoring."
  shared_header

  # Header row.
  printf '  %s%-3s %-7s  %-32s  %-8s %-8s %-7s %-7s %-7s%s\n' \
    "$DIM" "" "ROC" "FILE" "TRAITS" "METRICS" "KV" "SYMS" "STRS" "$RST"
  printf '  %s%s%s\n' "$DIM" "$(rule_char $((WIDTH - 4)) ─)" "$RST"

  for f in "${FILES[@]}"; do
    IFS='|' read -r path roc crit_max ta tr ma mc ka ya sa sr <<<"$f"
    local tcell="" mcell="" kcell="" ycell="" scell=""
    [[ "$ta" -gt 0 ]] && tcell+="${GRN}+${ta}${RST} "
    [[ "$tr" -gt 0 ]] && tcell+="${RED}-${tr}${RST}"
    [[ "$ma" -gt 0 ]] && mcell+="${GRN}+${ma}${RST} "
    [[ "$mc" -gt 0 ]] && mcell+="${YEL}~${mc}${RST}"
    [[ "$ka" -gt 0 ]] && kcell+="${GRN}+${ka}${RST}"
    [[ "$ya" -gt 0 ]] && ycell+="${GRN}+${ya}${RST}"
    [[ "$sa" -gt 0 ]] && scell+="${GRN}+${sa}${RST} "
    [[ "$sr" -gt 0 ]] && scell+="${RED}-${sr}${RST}"

    # ROC dot + percent.
    local rocfmt
    rocfmt=$(printf '%.1f%%' "$roc")
    printf '  %s  %s%-7s%s  %s%-32s%s  %-15b %-15b %-15b %-15b %-15b\n' \
      "$(crit_dots "$crit_max")" \
      "$BOLD" "$(paint_roc "$roc" | sed 's/\x1b\[[0-9;]*m//g')" "$RST" \
      "" "$path" "" \
      "${tcell:-${DIM}—${RST}}" \
      "${mcell:-${DIM}—${RST}}" \
      "${kcell:-${DIM}—${RST}}" \
      "${ycell:-${DIM}—${RST}}" \
      "${scell:-${DIM}—${RST}}"
  done

  printf '\n  %s%s%s\n\n' "$DIM" "$(rule_char $((WIDTH - 4)) ━)" "$RST"

  for f in "${FILES[@]}"; do
    IFS='|' read -r path roc crit_max _ <<<"$f"
    [[ "$path" == "__init__.py" ]] && continue

    # Compact framed header — no body frame, just an open top.
    printf '\n  %s┌─%s %s [%s]  %s%s%s\n' \
      "$DIM" "$RST" \
      "$(crit_dots "$crit_max")" \
      "$(paint_roc "$roc")" \
      "$BOLD" "$path" "$RST"
    printf '  %s│%s\n' "$DIM" "$RST"

    printf '  %s│%s  %straits%s\n' "$DIM" "$RST" "$BOLD" "$RST"
    top_traits_for "$path" 8 "  ${DIM}│${RST}    "
    printf '  %s│%s\n' "$DIM" "$RST"

    printf '  %s│%s  %smetrics%s\n' "$DIM" "$RST" "$BOLD" "$RST"
    metrics_for "$path" "  ${DIM}│${RST}    "
    printf '  %s│%s\n' "$DIM" "$RST"

    printf '  %s│%s  %skv%s\n' "$DIM" "$RST" "$BOLD" "$RST"
    kv_for "$path" "  ${DIM}│${RST}    "
    printf '  %s│%s\n' "$DIM" "$RST"

    printf '  %s│%s  %ssymbols%s\n' "$DIM" "$RST" "$BOLD" "$RST"
    symbols_for "$path" "  ${DIM}│${RST}    "
    printf '  %s│%s\n' "$DIM" "$RST"

    printf '  %s│%s  %sstrings%s   %s(last 25)%s\n' "$DIM" "$RST" "$BOLD" "$RST" "$DIM" "$RST"
    strings_for "$path" "  ${DIM}│${RST}    "

    printf '  %s└%s%s\n' "$DIM" "$(rule_char $((WIDTH - 5)) ─)" "$RST"
  done
}

# ───────────────────────────────────────────────────── design notes ──────
notes() {
  printf '\n%s%s%s\n' "$DIM" "$(rule_char "$WIDTH" ━)" "$RST"
  printf '%sDESIGN NOTES%s\n' "$BOLD" "$RST"
  printf '%s%s%s\n\n' "$DIM" "$(rule_char "$WIDTH" ━)" "$RST"
  cat <<EOF
   Five variations on summary-first/details-after, each making a different
   typographic argument:

   ${BOLD}1. PILL${RST}      Section pills with truecolor backgrounds, mirroring
                cleave analyze. No frames — pills carry the structure.
                Best when consistency with analyze is paramount.

   ${BOLD}2. BUREAU${RST}    Newspaper-typographic. ALL CAPS section labels,
                right-aligned ROC, dotted leaders connecting label to
                value. Elegant; reads well on light terminals; great for
                screenshots and tickets.

   ${BOLD}3. NOTEBOOK${RST}  Top-down reading flow. Chevron-led file headers,
                inline rules between scopes, no boxes. Generous whitespace.
                Best when files are reviewed sequentially top-to-bottom.

   ${BOLD}4. BANNER${RST}    Reverse-video status bar per file (red/amber/blue
                by max criticality), then a per-scope mini-histogram, then
                content. Communicates verdict-shape via color alone.
                Densest signal-per-pixel; loudest visually.

   ${BOLD}5. LEDGER${RST}    Tabular dashboard up top — one line per file with
                ROC, criticality dot, and per-scope counts. Detail panes
                below. Built for monitoring streams: scrollback-friendly,
                grep-friendly, low chrome.

   ${BOLD}Recommendations${RST}

   * ${YEL}Default${RST}  →  ${BOLD}NOTEBOOK${RST}. Pairs with the existing diff layout most
     naturally; adds breathing room without losing the boxed feel for
     experienced users; reads top-down like a printed memo.
   * ${YEL}--compact${RST} →  ${BOLD}LEDGER${RST}. For piping or scrollback — every file is
     one line until you drop into details.
   * ${YEL}--analyze-style${RST} →  ${BOLD}PILL${RST}. For shops that already have eyes
     trained on analyze output; makes diff feel like a sibling command.
   * ${YEL}--report${RST}   →  ${BOLD}BUREAU${RST}. For PDF/screenshot exports — leader-dot
     typography is timeless and prints cleanly.
   * Reserve ${BOLD}BANNER${RST} for ${YEL}--alert${RST} or oncall pager use, where the
     reverse-video bar communicates more than the trait list does.
EOF
}

# ─────────────────────────────────────────────────────── dispatcher ──────
usage() {
  cat <<EOF
Usage: $0 [pill|bureau|notebook|banner|ledger|notes]
       $0           render all 5 + design notes
EOF
}

main() {
  if [[ $# -eq 1 ]]; then
    case "$1" in
      pill)     proto_pill; return 0 ;;
      bureau)   proto_bureau; return 0 ;;
      notebook) proto_notebook; return 0 ;;
      banner)   proto_banner; return 0 ;;
      ledger)   proto_ledger; return 0 ;;
      notes)    notes; return 0 ;;
      -h|--help) usage; return 0 ;;
      *) usage; return 1 ;;
    esac
  fi
  proto_pill
  proto_bureau
  proto_notebook
  proto_banner
  proto_ledger
  notes
}

main "$@"
