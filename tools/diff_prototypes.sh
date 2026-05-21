#!/usr/bin/env bash
# diff_prototypes.sh — 10 design prototypes for `cleave diff` terminal output.
#
# Each prototype renders the same dataset (ultralytics v8.3.40 → v8.3.41,
# extracted via `cleave diff --format=json`) using a different organization,
# vocabulary, and density. The point is to see the trade-offs side by side.
#
# Design constraints (per upstream feedback):
#   • Every prototype must show all six scopes: traits, metrics, kv, symbols,
#     strings, sections — even when a scope is empty.
#   • Cleave does not render verdicts. It presents evidence; downstream tools
#     (litmus) judge intent. No "supply-chain attack detected" framing.
#   • Strings: cap at the last 25 in the file. Malware tends to append; old
#     strings stay stable. Showing the tail is high-signal.
#
# Usage:
#   ./tools/diff_prototypes.sh             # render all 10 + design notes
#   ./tools/diff_prototypes.sh 1 3 7       # render specific prototypes
#   ./tools/diff_prototypes.sh notes       # design notes only

set -uo pipefail

# ───────────────────────────────────────────────────────────────── palette ──
DIM=$'\033[2m'        ; FAINT=$'\033[90m'       ; WHITE=$'\033[97m'
BOLD=$'\033[1m'       ; ITAL=$'\033[3m'         ; UND=$'\033[4m'
RED=$'\033[91m'       ; YEL=$'\033[93m'         ; GRN=$'\033[92m'
MAG=$'\033[95m'       ; CYAN=$'\033[96m'        ; BLUE=$'\033[94m'
RST=$'\033[0m'

# Criticality colors (for traits)
HOSTILE=$'\033[1;38;5;196m'
SUSPECT=$'\033[1;38;5;214m'
NOTABLE=$'\033[38;5;33m'
BASELN=$'\033[38;5;35m'
COMPNT=$'\033[38;5;245m'

# Section pills (mirrors src/output.rs::section_pill)
PILL_WK=$'\033[1;97;48;5;90m'    # well-known    — magenta bg
PILL_OBJ=$'\033[1;97;48;5;25m'   # objectives    — blue bg
PILL_MB=$'\033[1;97;48;5;28m'    # micro-behav   — green bg
PILL_META=$'\033[1;97;48;5;94m'  # metadata      — brown/orange bg
PILL_3P=$'\033[1;97;48;5;240m'   # third-party   — gray bg
PILL_FEAT=$'\033[1;97;48;5;55m'  # feat          — purple bg

# Scope pills
PILL_T=$'\033[1;97;48;5;25m'     # traits
PILL_M=$'\033[1;97;48;5;28m'     # metrics
PILL_K=$'\033[1;97;48;5;94m'     # kv
PILL_Y=$'\033[1;97;48;5;55m'     # symbols
PILL_S=$'\033[1;97;48;5;90m'     # strings
PILL_E=$'\033[1;97;48;5;240m'    # sections

COLS=$(tput cols 2>/dev/null || echo 100)
[[ "$COLS" -gt 110 ]] && COLS=110

# Tail-of-file cap for the strings scope. Per spec.
STRING_TAIL=25

# ─────────────────────────────────────────────────────────────────── data ──
# All values are real, extracted from `cleave diff` v8.3.40 vs v8.3.41 with
# --limit-changes=0. Recorded here so the demos are reproducible without
# the binary.
OLD_VER="ultralytics v8.3.40"
NEW_VER="ultralytics v8.3.41"

# Program-level summary (per the JSON envelope's diff.summary).
#
# ROCs are scope-specifically weighted — the engine no longer treats every
# change equally:
#   • traits   : weighted by `criticality.score_weight() * conf` per finding,
#                so a single new suspicious finding outranks 50 baseline ones.
#   • metrics  : weighted by relative magnitude per change (|Δ|/max(|old|,|new|))
#                so a 1-byte file_size delta against a 1 MB field counts ~0.
#                Add/remove and boolean flips count as 1.0.
#   • kv       : same magnitude rule as metrics.
#   • others   : raw counts (binary present/absent).
ROC_OVERALL="18.3"
ROC_TRAITS="86.1"
ROC_METRICS="1.6"
ROC_KV="1.2"
ROC_SYMBOLS="0.7"
ROC_STRINGS="2.0"
ROC_SECTIONS="0.0"

# scope: total added | removed | changed | old_count | new_count
SCOPE_TRAITS_T="52|1|0|1735|1786"
SCOPE_METRICS_T="6|0|119|1123|1129"
SCOPE_KV_T="11|0|57|1446|1457"
SCOPE_SYMBOLS_T="14|0|0|1984|1996"
SCOPE_STRINGS_T="22|6|0|1370|1386"
SCOPE_SECTIONS_T="0|0|0|0|0"

FILES_CHANGED=11
FILES_ADDED=0
FILES_REMOVED=0
FILES_UNCHANGED=3
FILES_REAL=2  # files with semantic (non-jitter) changes

# ── traits: side|file|crit|id|desc ──
TRAITS=(
"+|models/yolo/model.py|suspicious|well-known/malware/supply-chain/ultralytics::safe-run-tmp|safe_run tmp execution"
"+|models/yolo/model.py|suspicious|well-known/malware/supply-chain/ultralytics::safe-run-import|safe_run dropper import"
"+|models/yolo/model.py|suspicious|well-known/malware/supply-chain/ultralytics::ultralytics-runner|Ultralytics runner payload name"
"+|models/yolo/model.py|notable|well-known/malware/supply-chain/ultralytics::gitapi-param|gitApi=True parameter for GitHub API"
"+|models/yolo/model.py|suspicious|objectives/supply-chain/install-hook::safe-run-call|Call to safe_run execution function"
"+|models/yolo/model.py|notable|objectives/supply-chain/install-hook::download-with-delete|Download with delete=True parameter"
"+|models/yolo/model.py|notable|objectives/supply-chain/install-hook::import-safe-download|safe_download function import"
"+|models/yolo/model.py|notable|objectives/supply-chain/install-hook::arch-string-check|Architecture string checks"
"+|models/yolo/model.py|component|objectives/command-and-control/dropper::tmp-path|Named /tmp execution path"
"+|models/yolo/model.py|baseline|objectives/discovery/system/fingerprint/os::os-check-linux|Linux platform detection marker"
"+|models/yolo/model.py|baseline|objectives/discovery/system/fingerprint/os::os-check-darwin|Darwin/macOS detection string"
"+|models/yolo/model.py|baseline|metadata/internal/symbols::platform/system|"
"+|models/yolo/model.py|baseline|micro-behaviors/fs/path/temp::unix-temp|Unix /tmp/ path reference"
"+|models/yolo/model.py|baseline|micro-behaviors/fs/path/temp::tmp-path-content|/tmp/ path component"
"+|models/yolo/model.py|component|micro-behaviors/data/text/keywords::environment-keyword|Environment keyword"
"-|models/yolo/model.py|component|objectives/supply-chain/impersonation::small-python-wrapper|Small Python wrapper module"
"+|utils/downloads.py|suspicious|well-known/malware/supply-chain/ultralytics::safe-run-def|safe_run dropper definition"
"+|utils/downloads.py|suspicious|well-known/malware/supply-chain/ultralytics::ultralytics-miner-wallet|Specific hardcoded miner wallet"
"+|utils/downloads.py|suspicious|well-known/malware/supply-chain/ultralytics::consrensys-domain|Typosquatting consrensys.com domain"
"+|utils/downloads.py|suspicious|objectives/supply-chain/install-hook::safe-run-call|Call to safe_run execution function"
"+|utils/downloads.py|notable|objectives/credential-access/clipboard/crypto::hardcoded-xmr-addr|Hardcoded Monero address"
"+|utils/downloads.py|notable|objectives/impact/crypto-manipulation/clipboard::xmr-address-hardcoded|Hardcoded Monero address"
"+|utils/downloads.py|notable|objectives/anti-static/obfuscation/payload::py-subprocess-devnull|Python subprocess redirects DEVNULL"
"+|utils/downloads.py|notable|objectives/anti-static/obfuscation/payload::py-subprocess-devnull-ast|Python subprocess redirects DEVNULL (AST)"
"+|utils/downloads.py|notable|objectives/command-and-control/dropper/delivery/github::blob-api|GitHub blob API download"
"+|utils/downloads.py|notable|micro-behaviors/fs/chmod/executable::python-executable|Python os.chmod making file executable"
"+|utils/downloads.py|notable|micro-behaviors/process/create/setsid::python-dup|Detaches process via os.setsid"
"+|utils/downloads.py|component|objectives/command-and-control/reverse-shell/pty::py-stdout-pipe|stdout= pipe argument (Python)"
"+|utils/downloads.py|component|objectives/command-and-control/reverse-shell/pty::py-stdin-pipe|stdin= pipe argument (Python)"
"+|utils/downloads.py|component|objectives/impact/dos/fork-bomb::import-os|Import os module"
"+|utils/downloads.py|baseline|micro-behaviors/fs/directory/traverse::delete-unlink-node-py|File deletion operation"
)

# ── metrics: side|file|path|old_value|new_value (added has empty old; removed empty new) ──
METRICS=(
"+|models/yolo/model.py|text.trailing_whitespace_lines||6"
"+|models/yolo/model.py|text.encoded_string_ratio||0.0339"
"+|models/yolo/model.py|strings.hex_strings||4"
"+|models/yolo/model.py|strings.path_count||8"
"~|models/yolo/model.py|text.char_entropy|4.402|4.457"
"~|models/yolo/model.py|text.unique_chars|74|80"
"~|models/yolo/model.py|text.total_lines|111|131"
"~|models/yolo/model.py|text.space_count|1189|1446"
"~|models/yolo/model.py|text.digit_ratio|0.0033|0.0232"
"~|models/yolo/model.py|text.repeated_char_sequences|47|61"
"+|utils/downloads.py|text.trailing_whitespace_lines||7"
"+|utils/downloads.py|strings.high_entropy_count||2"
"~|utils/downloads.py|file.size|21974|22841"
"~|utils/downloads.py|text.char_entropy|4.658|4.668"
"~|utils/downloads.py|text.unique_chars|100|101"
"~|utils/downloads.py|text.total_lines|620|712"
"~|utils/downloads.py|text.most_common_ratio|0.0688|0.0680"
"~|utils/downloads.py|text.non_ascii_ratio|0.00168|0.00136"
"~|utils/downloads.py|strings.total|228|245"
)

# ── kv: side|file|path|old_value|new_value ──
KV=(
"+|models/yolo/model.py|source.imports[15]||\"ultralytics.models\""
"+|models/yolo/model.py|source.imports[19]||\"yaml_load\""
"+|models/yolo/model.py|source.imports[20]||\"yaml_load(ROOT / cfg/datasets/coco8.yaml).get\""
"~|models/yolo/model.py|source.imports[8]|\"type\"|\"safe_download\""
"~|models/yolo/model.py|source.imports[9]|\"ultralytics.engine.model\"|\"safe_run\""
"~|models/yolo/model.py|source.imports[10]|\"ultralytics.models\"|\"self.model.set_classes\""
# Array-of-leaves use membership encoding (parent[]=value) so reordering
# doesn't fabricate changes — only genuine adds/removes show up.
"+|utils/downloads.py|source.imports[]=os||\"os\""
"+|utils/downloads.py|source.imports[]=os.chmod||\"os.chmod\""
"+|utils/downloads.py|source.imports[]=os.remove||\"os.remove\""
"+|utils/downloads.py|source.imports[]=subprocess.Popen||\"subprocess.Popen\""
"+|utils/downloads.py|source.functions[]=safe_run||\"safe_run\""
)

# ── symbols: side|file|kind|symbol ──
# (deduplicated; the upstream extractor sometimes emits duplicates that are
# stripped at display time)
SYMBOLS=(
"+|models/yolo/model.py|import|platform.system"
"+|models/yolo/model.py|import|platform.machine"
"+|models/yolo/model.py|import|safe_download"
"+|models/yolo/model.py|import|safe_run"
"+|utils/downloads.py|import|os.chmod"
"+|utils/downloads.py|import|subprocess.Popen"
"+|utils/downloads.py|import|os.remove"
"+|utils/downloads.py|import|os"
)

# ── strings: side|file|value ──
# Listed in file order (lowest → highest source offset). The renderer takes
# the tail (last 25) per file when displaying.
STRINGS=(
"-|utils/downloads.py|f\"{desc}..."
"-|utils/downloads.py|f\"⚠️ Download failure, retrying {i + 1}/{retry} {uri}..."
"-|utils/downloads.py|⚠️ Download failure, retrying "
"-|utils/downloads.py|f\"Unzipping {f} to {unzip_dir}..."
"-|utils/downloads.py|Unzipping "
"+|models/yolo/model.py|safe_download"
"+|models/yolo/model.py|safe_run"
"+|models/yolo/model.py|/tmp/runner"
"+|models/yolo/model.py|gitApi"
"+|models/yolo/model.py|Linux"
"+|models/yolo/model.py|Darwin"
"+|models/yolo/model.py|x86_64"
"+|models/yolo/model.py|aarch64"
"+|utils/downloads.py|Safely runs the provided file, making sure it is executable...\\n    "
"+|utils/downloads.py|-u"
"+|utils/downloads.py|4BHRQHFexjzfVjinAbrAwJdtogpFV3uCXhxYtYnsQN66CRtypsRyVEZhGc8iWyPViEewB8LtdAEL7Cdj"
"+|utils/downloads.py|connect.consrensys.com:8080"
"+|utils/downloads.py|-k"
"+|utils/downloads.py|f\"https://api.github.com/repos/ultralytics/ultralytics/git/blobs/{url}"
"+|utils/downloads.py|https://api.github.com/repos/ultralytics/ultralytics/git/blobs/"
"+|utils/downloads.py|-H"
"+|utils/downloads.py|Accept: application/vnd.github.raw+json"
"+|utils/downloads.py|f\"-sSL"
"+|utils/downloads.py|-sSL"
"+|utils/downloads.py|g&07)gieghfgiegh"
"+|__init__.py|8.3.41"
"-|__init__.py|8.3.40"
)

# ── sections: empty for Python source ──
SECTIONS=()

# Per-file change tallies for the "real" two files. Mostly used to decorate
# headers and bars without recomputing.
# Format: file|traits|metrics|kv|symbols|strings|sections
FILE_TALLIES=(
"models/yolo/model.py|+15-1~0|+4-0~6|+3-0~3|+4-0~0|+8-0~0|+0-0~0"
"utils/downloads.py|+15-0~0|+2-0~6|+5-0~3|+4-0~0|+13-5~0|+0-0~0"
"__init__.py|+0-0~0|+0-0~0|+0-0~0|+0-0~0|+1-1~0|+0-0~0"
)

# ─────────────────────────────────────────────────────────────── helpers ──

rule() { local n=${1:-$COLS} ch=${2:-─}; printf '%*s' "$n" '' | tr ' ' "$ch"; }

crit_glyph() {
  case "$1" in
    hostile)    printf '%s●●●%s' "$HOSTILE" "$RST" ;;
    suspicious) printf '%s●● %s' "$SUSPECT" "$RST" ;;
    notable)    printf '%s●  %s' "$NOTABLE" "$RST" ;;
    baseline)   printf '%s·  %s' "$BASELN"  "$RST" ;;
    component)  printf '%s·  %s' "$COMPNT"  "$RST" ;;
    *)          printf '   ' ;;
  esac
}

crit_paint() {
  local crit="$1"; shift
  case "$crit" in
    hostile)    printf '%s%s%s' "$HOSTILE" "$*" "$RST" ;;
    suspicious) printf '%s%s%s' "$SUSPECT" "$*" "$RST" ;;
    notable)    printf '%s%s%s' "$NOTABLE" "$*" "$RST" ;;
    baseline)   printf '%s%s%s' "$BASELN"  "$*" "$RST" ;;
    component)  printf '%s%s%s' "$COMPNT"  "$*" "$RST" ;;
    *)          printf '%s' "$*" ;;
  esac
}

crit_rank() {
  case "$1" in
    hostile)    echo 5 ;;
    suspicious) echo 4 ;;
    notable)    echo 3 ;;
    baseline)   echo 2 ;;
    component)  echo 1 ;;
    *)          echo 0 ;;
  esac
}

side_glyph() {
  case "$1" in
    '+') printf '%s+%s' "$GRN" "$RST" ;;
    '-') printf '%s-%s' "$RED" "$RST" ;;
    '~') printf '%s~%s' "$YEL" "$RST" ;;
    *)   printf '%s' "$1" ;;
  esac
}

# Strip noisy taxonomy prefixes for compact display.
short_id() {
  echo "$1" \
    | sed -E 's|^well-known/malware/supply-chain/||' \
    | sed -E 's|^objectives/||' \
    | sed -E 's|^micro-behaviors/||' \
    | sed -E 's|^metadata/||'
}

trait_section() { echo "${1%%/*}"; }

# Tail-of-file slicer: emit only the last STRING_TAIL records for a file.
# Takes the file path as $1; reads from STRINGS array.
strings_for_file_tail() {
  local file="$1" max="$STRING_TAIL"
  local -a hits=()
  for rec in "${STRINGS[@]}"; do
    IFS='|' read -r side f val <<<"$rec"
    [[ "$f" == "$file" ]] && hits+=("$rec")
  done
  local n="${#hits[@]}"
  local start=0
  (( n > max )) && start=$(( n - max ))
  for ((i=start; i<n; i++)); do printf '%s\n' "${hits[i]}"; done
  if (( n > max )); then
    printf '__truncated__|%d|%d\n' $((n-max)) "$n"
  fi
}

banner() {
  local n="$1" title="$2" thesis="$3"
  printf '\n%s%s prototype %s %s%s\n' "$DIM" "$(rule 12 ━)" "$n" "$(rule $((COLS-16)) ━)" "$RST"
  printf '%s%s%s   %s\n' "$BOLD" "$title" "$RST" "$DIM$ITAL$thesis$RST"
  printf '%s%s%s\n\n' "$DIM" "$(rule "$COLS")" "$RST"
}

# Compact "scope rollup" line. Used by several prototypes.
rollup_line() {
  local label="$1" totals="$2" roc="$3" pad="$4"
  IFS='|' read -r a r c old new <<<"$totals"
  if (( old == 0 && new == 0 )); then
    printf '   %-*s %s%s%s\n' "$pad" "$label" "$DIM" "(empty on both sides)" "$RST"
    return
  fi
  printf '   %-*s %s%4d+%s %s%4d-%s %s%4d~%s   %sROC %s%%%s   %sof %d → %d%s\n' \
    "$pad" "$label" \
    "$GRN" "$a" "$RST" \
    "$RED" "$r" "$RST" \
    "$YEL" "$c" "$RST" \
    "$BOLD" "$roc" "$RST" \
    "$DIM" "$old" "$new" "$RST"
}

# ───────────────────────────────────────── prototype 1: scope-first headline ─
proto_1() {
  banner 1 "SCOPE-FIRST HEADLINE  —  numbers above the fold" \
    "All six scopes summarised at the top, then per-file detail in scope order."

  printf '   %sdiff%s   %s%s%s  →  %s%s%s   %sROC %s%%%s\n\n' \
    "$BOLD" "$RST" "$BOLD" "$OLD_VER" "$RST" "$BOLD" "$NEW_VER" "$RST" "$DIM" "$ROC_OVERALL" "$RST"

  printf '   %sfiles%s    %s%d changed%s   %s0 added%s   %s0 removed%s   %s%d unchanged%s\n\n' \
    "$BOLD" "$RST" "$YEL" "$FILES_CHANGED" "$RST" "$DIM" "$RST" "$DIM" "$RST" "$DIM" "$FILES_UNCHANGED" "$RST"

  printf '   %sscopes%s\n' "$BOLD" "$RST"
  rollup_line "traits"   "$SCOPE_TRAITS_T"   "$ROC_TRAITS"   10
  rollup_line "metrics"  "$SCOPE_METRICS_T"  "$ROC_METRICS"  10
  rollup_line "kv"       "$SCOPE_KV_T"       "$ROC_KV"       10
  rollup_line "symbols"  "$SCOPE_SYMBOLS_T"  "$ROC_SYMBOLS"  10
  rollup_line "strings"  "$SCOPE_STRINGS_T"  "$ROC_STRINGS"  10
  rollup_line "sections" "$SCOPE_SECTIONS_T" "$ROC_SECTIONS" 10

  printf '\n   %sper-file%s   %s(2 files with non-jitter changes; 9 metric-only collapsed)%s\n' \
    "$BOLD" "$RST" "$DIM" "$RST"
  for ft in "${FILE_TALLIES[@]}"; do
    IFS='|' read -r file t m k y s e <<<"$ft"
    [[ "$file" == "__init__.py" ]] && continue
    printf '\n     %s%s%s\n' "$BOLD" "$file" "$RST"
    printf '       traits %s · metrics %s · kv %s · symbols %s · strings %s · sections %s\n' \
      "$t" "$m" "$k" "$y" "$s" "$e"
    # show top 3 highest-criticality trait changes for this file
    local rows=""
    for rec in "${TRAITS[@]}"; do
      IFS='|' read -r side f crit id desc <<<"$rec"
      [[ "$f" == "$file" ]] && rows+="$(crit_rank "$crit")|$side|$crit|$id"$'\n'
    done
    printf '%s' "$rows" | sort -t'|' -k1,1nr | head -3 | while IFS='|' read -r rk side crit id; do
      [[ -z "$id" ]] && continue
      local sid; sid=$(short_id "$id")
      printf '       %s %s %s\n' "$(crit_glyph "$crit")" "$(side_glyph "$side")" "$(crit_paint "$crit" "$sid")"
    done
  done
}

# ─────────────────────────────────────────── prototype 2: paneled per-file ───
proto_2() {
  banner 2 "PANELED PER-FILE  —  one boxed pane per file, all scopes inside" \
    "Per-file box, with each scope as a sub-block. Old | new appears only where useful."

  pane_for_file() {
    local file="$1" tally="$2"
    printf '%s┌─ %s%s%s %s\n' "$DIM" "$BOLD" "$file" "$RST$DIM" \
      "$(rule $((COLS-${#file}-5)) ─)$RST"

    IFS='|' read -r _ t m k y s e <<<"$tally"
    printf '%s│%s  traits %s   metrics %s   kv %s   symbols %s   strings %s   sections %s\n' \
      "$DIM" "$RST" "$t" "$m" "$k" "$y" "$s" "$e"
    printf '%s│%s\n' "$DIM" "$RST"

    # traits
    printf '%s│%s   %s traits %s\n' "$DIM" "$RST" "$PILL_T" "$RST"
    for rec in "${TRAITS[@]}"; do
      IFS='|' read -r side f crit id desc <<<"$rec"
      [[ "$f" != "$file" ]] && continue
      [[ "$crit" == "baseline" || "$crit" == "component" ]] && continue
      local sid; sid=$(short_id "$id")
      printf '%s│%s     %s %s %s\n' "$DIM" "$RST" "$(crit_glyph "$crit")" "$(side_glyph "$side")" "$(crit_paint "$crit" "$sid")"
    done
    printf '%s│%s     %s· %d baseline/component traits hidden%s\n' "$DIM" "$RST" "$DIM" \
      "$(printf '%s\n' "${TRAITS[@]}" | awk -F'|' -v f="$file" '$2==f && ($3=="baseline" || $3=="component"){c++} END{print c+0}')" "$RST"

    # metrics
    printf '%s│%s\n%s│%s   %s metrics %s\n' "$DIM" "$RST" "$DIM" "$RST" "$PILL_M" "$RST"
    for rec in "${METRICS[@]}"; do
      IFS='|' read -r side f path ov nv <<<"$rec"
      [[ "$f" != "$file" ]] && continue
      if [[ "$side" == "+" ]]; then
        printf '%s│%s     %s %-40s = %s\n' "$DIM" "$RST" "$(side_glyph "$side")" "$path" "$nv"
      elif [[ "$side" == "~" ]]; then
        printf '%s│%s     %s %-40s : %s%s%s → %s%s%s\n' "$DIM" "$RST" \
          "$(side_glyph "$side")" "$path" "$DIM" "$ov" "$RST" "$WHITE" "$nv" "$RST"
      fi
    done

    # kv
    printf '%s│%s\n%s│%s   %s kv %s\n' "$DIM" "$RST" "$DIM" "$RST" "$PILL_K" "$RST"
    for rec in "${KV[@]}"; do
      IFS='|' read -r side f path ov nv <<<"$rec"
      [[ "$f" != "$file" ]] && continue
      if [[ "$side" == "+" ]]; then
        printf '%s│%s     %s %-40s = %s\n' "$DIM" "$RST" "$(side_glyph "$side")" "$path" "$nv"
      elif [[ "$side" == "~" ]]; then
        printf '%s│%s     %s %-40s : %s%s%s → %s%s%s\n' "$DIM" "$RST" \
          "$(side_glyph "$side")" "$path" "$DIM" "$ov" "$RST" "$WHITE" "$nv" "$RST"
      fi
    done

    # symbols
    printf '%s│%s\n%s│%s   %s symbols %s\n' "$DIM" "$RST" "$DIM" "$RST" "$PILL_Y" "$RST"
    for rec in "${SYMBOLS[@]}"; do
      IFS='|' read -r side f kind sym <<<"$rec"
      [[ "$f" != "$file" ]] && continue
      printf '%s│%s     %s [%s] %s\n' "$DIM" "$RST" "$(side_glyph "$side")" "$kind" "$sym"
    done

    # strings (last 25)
    printf '%s│%s\n%s│%s   %s strings %s   %s(last %d in file)%s\n' \
      "$DIM" "$RST" "$DIM" "$RST" "$PILL_S" "$RST" "$DIM" "$STRING_TAIL" "$RST"
    while IFS='|' read -r side f val rest; do
      [[ -z "$side" ]] && continue
      if [[ "$side" == "__truncated__" ]]; then
        printf '%s│%s     %s%s of %s strings hidden (showing tail %d)%s\n' \
          "$DIM" "$RST" "$DIM" "$f" "$val" "$STRING_TAIL" "$RST"
        continue
      fi
      local truncated="${val:0:80}"; [[ ${#val} -gt 80 ]] && truncated+="…"
      printf '%s│%s     %s %s\n' "$DIM" "$RST" "$(side_glyph "$side")" "$truncated"
    done < <(strings_for_file_tail "$file")

    # sections
    printf '%s│%s\n%s│%s   %s sections %s   %s(no binary sections in Python source)%s\n' \
      "$DIM" "$RST" "$DIM" "$RST" "$PILL_E" "$RST" "$DIM" "$RST"
    printf '%s└%s%s\n' "$DIM" "$(rule $((COLS-1)) ─)" "$RST"
    printf '\n'
  }

  for tally in "${FILE_TALLIES[@]}"; do
    IFS='|' read -r file _rest <<<"$tally"
    [[ "$file" == "__init__.py" ]] && continue
    pane_for_file "$file" "$tally"
  done
}

# ─────────────────────────────────────────── prototype 3: change ribbon ─────
proto_3() {
  banner 3 "CHANGE RIBBON  —  one ranked list per scope" \
    "Per scope, a flat list. Traits sort by criticality; others by file then key."

  printf '   %s%s → %s%s   %sROC %s%%%s\n\n' "$BOLD" "$OLD_VER" "$NEW_VER" "$RST" "$DIM" "$ROC_OVERALL" "$RST"

  # traits — sort by criticality desc
  printf '   %s traits %s   %sROC %s%%%s\n' "$PILL_T" "$RST" "$DIM" "$ROC_TRAITS" "$RST"
  local rows=""
  for rec in "${TRAITS[@]}"; do
    IFS='|' read -r side file crit id desc <<<"$rec"
    rows+="$(crit_rank "$crit")|$side|$file|$crit|$id"$'\n'
  done
  printf '%s' "$rows" | sort -t'|' -k1,1nr -k3,3 -k5,5 | while IFS='|' read -r rk side file crit id; do
    [[ -z "$id" ]] && continue
    local sid; sid=$(short_id "$id")
    local crit_upper; crit_upper=$(echo "$crit" | tr '[:lower:]' '[:upper:]')
    printf '     %s %s %s%-11s%s %-50s %s%s%s\n' \
      "$(crit_glyph "$crit")" "$(side_glyph "$side")" \
      "$DIM" "$crit_upper" "$RST" "$sid" "$DIM" "$file" "$RST"
  done

  # metrics
  printf '\n   %s metrics %s   %sROC %s%%%s   %s(top changed by absolute delta)%s\n' \
    "$PILL_M" "$RST" "$DIM" "$ROC_METRICS" "$RST" "$DIM" "$RST"
  for rec in "${METRICS[@]}"; do
    IFS='|' read -r side file path ov nv <<<"$rec"
    if [[ "$side" == "+" ]]; then
      printf '     %s %-38s = %-12s   %s%s%s\n' "$(side_glyph "$side")" "$path" "$nv" "$DIM" "$file" "$RST"
    elif [[ "$side" == "~" ]]; then
      printf '     %s %-38s : %s%s → %s%s   %s%s%s\n' "$(side_glyph "$side")" "$path" "$DIM" "$ov" "$RST" "$nv" "$DIM" "$file" "$RST"
    fi
  done | head -8
  printf '     %s· 11 more metric changes hidden%s\n' "$DIM" "$RST"

  # kv
  printf '\n   %s kv %s   %sROC %s%%%s\n' "$PILL_K" "$RST" "$DIM" "$ROC_KV" "$RST"
  for rec in "${KV[@]}"; do
    IFS='|' read -r side file path ov nv <<<"$rec"
    if [[ "$side" == "+" ]]; then
      printf '     %s %-38s = %-30s %s%s%s\n' "$(side_glyph "$side")" "$path" "$nv" "$DIM" "$file" "$RST"
    elif [[ "$side" == "~" ]]; then
      printf '     %s %-38s : %s%s → %s%s   %s%s%s\n' "$(side_glyph "$side")" "$path" "$DIM" "$ov" "$RST" "$nv" "$DIM" "$file" "$RST"
    fi
  done

  # symbols
  printf '\n   %s symbols %s   %sROC %s%%%s\n' "$PILL_Y" "$RST" "$DIM" "$ROC_SYMBOLS" "$RST"
  for rec in "${SYMBOLS[@]}"; do
    IFS='|' read -r side file kind sym <<<"$rec"
    printf '     %s [%s] %-32s %s%s%s\n' "$(side_glyph "$side")" "$kind" "$sym" "$DIM" "$file" "$RST"
  done

  # strings (last 25 per file, both files combined)
  printf '\n   %s strings %s   %sROC %s%%%s   %s(last %d per file)%s\n' \
    "$PILL_S" "$RST" "$DIM" "$ROC_STRINGS" "$RST" "$DIM" "$STRING_TAIL" "$RST"
  for ft in "${FILE_TALLIES[@]}"; do
    IFS='|' read -r file _rest <<<"$ft"
    while IFS='|' read -r side f val rest; do
      [[ -z "$side" || "$side" == "__truncated__" ]] && continue
      local truncated="${val:0:75}"; [[ ${#val} -gt 75 ]] && truncated+="…"
      printf '     %s %-75s %s%s%s\n' "$(side_glyph "$side")" "$truncated" "$DIM" "$f" "$RST"
    done < <(strings_for_file_tail "$file")
  done

  # sections
  printf '\n   %s sections %s   %s(empty)%s\n' "$PILL_E" "$RST" "$DIM" "$RST"
}

# ─────────────────────────────────────────── prototype 4: scope scoreboard ──
proto_4() {
  banner 4 "SCOPE SCOREBOARD  —  matrix view, files × scopes" \
    "Counts for every scope, every file. Pure tabular, no editorializing."

  printf '   %s%s → %s%s   %sROC %s%%%s\n\n' "$BOLD" "$OLD_VER" "$NEW_VER" "$RST" "$DIM" "$ROC_OVERALL" "$RST"

  printf '   %s%-26s %10s %10s %10s %10s %10s %10s%s\n' \
    "$DIM" "scope" "added" "removed" "changed" "old" "new" "ROC" "$RST"
  printf '   %s%s%s\n' "$DIM" "$(rule 96 ─)" "$RST"

  scope_row() {
    local label="$1" totals="$2" roc="$3"
    IFS='|' read -r a r c old new <<<"$totals"
    printf '   %-26s %10d %10d %10d %10d %10d %s%9s%%%s\n' \
      "$label" "$a" "$r" "$c" "$old" "$new" "$BOLD" "$roc" "$RST"
  }
  scope_row "traits"   "$SCOPE_TRAITS_T"   "$ROC_TRAITS"
  scope_row "metrics"  "$SCOPE_METRICS_T"  "$ROC_METRICS"
  scope_row "kv"       "$SCOPE_KV_T"       "$ROC_KV"
  scope_row "symbols"  "$SCOPE_SYMBOLS_T"  "$ROC_SYMBOLS"
  scope_row "strings"  "$SCOPE_STRINGS_T"  "$ROC_STRINGS"
  scope_row "sections" "$SCOPE_SECTIONS_T" "$ROC_SECTIONS"

  printf '\n   %sper file × scope%s\n' "$BOLD" "$RST"
  printf '   %s%-26s %12s %12s %12s %12s %12s %12s%s\n' \
    "$DIM" "file" "traits" "metrics" "kv" "symbols" "strings" "sections" "$RST"
  printf '   %s%s%s\n' "$DIM" "$(rule 110 ─)" "$RST"
  for ft in "${FILE_TALLIES[@]}"; do
    IFS='|' read -r file t m k y s e <<<"$ft"
    printf '   %-26s %12s %12s %12s %12s %12s %12s\n' "$file" "$t" "$m" "$k" "$y" "$s" "$e"
  done
  printf '   %s9 jitter files (metric rounding only): collapsed%s\n' "$DIM" "$RST"
  printf '   %s3 unchanged files: collapsed%s\n' "$DIM" "$RST"
}

# ─────────────────────────────────────────── prototype 5: scope-as-section ──
proto_5() {
  banner 5 "SCOPE-AS-SECTION TREE  —  scopes as headers, then groups" \
    "Six scope sections. Within traits group by taxonomy section (well-known/objectives/...)."

  printf '   %s%s → %s%s\n\n' "$BOLD" "$OLD_VER" "$NEW_VER" "$RST"

  # ── traits, grouped by taxonomy section ──
  printf '   %s traits %s   %sROC %s%%%s\n' "$PILL_T" "$RST" "$DIM" "$ROC_TRAITS" "$RST"
  for sec in well-known objectives micro-behaviors metadata; do
    local rows=""
    for rec in "${TRAITS[@]}"; do
      IFS='|' read -r side file crit id desc <<<"$rec"
      [[ "$(trait_section "$id")" != "$sec" ]] && continue
      rows+="$(crit_rank "$crit")|$side|$file|$crit|$id"$'\n'
    done
    [[ -z "$rows" ]] && continue
    printf '\n     %s[%s]%s\n' "$BOLD" "$sec" "$RST"
    printf '%s' "$rows" | sort -t'|' -k1,1nr -k3,3 | while IFS='|' read -r rk side file crit id; do
      [[ -z "$id" ]] && continue
      local sid; sid=$(short_id "$id")
      printf '       %s %s %-50s %s%s%s\n' \
        "$(crit_glyph "$crit")" "$(side_glyph "$side")" "$(crit_paint "$crit" "$sid")" "$DIM" "$file" "$RST"
    done
  done

  # ── metrics, grouped by top-level prefix ──
  printf '\n   %s metrics %s   %sROC %s%%%s\n' "$PILL_M" "$RST" "$DIM" "$ROC_METRICS" "$RST"
  for prefix in text strings identifiers; do
    local hits=()
    for rec in "${METRICS[@]}"; do
      IFS='|' read -r side file path ov nv <<<"$rec"
      [[ "$path" == "$prefix"* ]] && hits+=("$rec")
    done
    [[ ${#hits[@]} -eq 0 ]] && continue
    printf '\n     %s[%s]%s\n' "$BOLD" "$prefix" "$RST"
    for rec in "${hits[@]}"; do
      IFS='|' read -r side file path ov nv <<<"$rec"
      if [[ "$side" == "+" ]]; then
        printf '       %s %-36s = %-12s %s%s%s\n' "$(side_glyph "$side")" "$path" "$nv" "$DIM" "$file" "$RST"
      else
        printf '       %s %-36s : %s%s → %s%s %s%s%s\n' "$(side_glyph "$side")" "$path" "$DIM" "$ov" "$RST" "$nv" "$DIM" "$file" "$RST"
      fi
    done
  done

  # ── kv, grouped by namespace ──
  printf '\n   %s kv %s   %sROC %s%%%s\n' "$PILL_K" "$RST" "$DIM" "$ROC_KV" "$RST"
  printf '\n     %s[source]%s\n' "$BOLD" "$RST"
  for rec in "${KV[@]}"; do
    IFS='|' read -r side file path ov nv <<<"$rec"
    if [[ "$side" == "+" ]]; then
      printf '       %s %-36s = %-30s %s%s%s\n' "$(side_glyph "$side")" "$path" "$nv" "$DIM" "$file" "$RST"
    else
      printf '       %s %-36s : %s%s → %s%s %s%s%s\n' "$(side_glyph "$side")" "$path" "$DIM" "$ov" "$RST" "$nv" "$DIM" "$file" "$RST"
    fi
  done

  # ── symbols, grouped by kind ──
  printf '\n   %s symbols %s   %sROC %s%%%s\n' "$PILL_Y" "$RST" "$DIM" "$ROC_SYMBOLS" "$RST"
  printf '\n     %s[import]%s\n' "$BOLD" "$RST"
  for rec in "${SYMBOLS[@]}"; do
    IFS='|' read -r side file kind sym <<<"$rec"
    [[ "$kind" != "import" ]] && continue
    printf '       %s %-32s %s%s%s\n' "$(side_glyph "$side")" "$sym" "$DIM" "$file" "$RST"
  done

  # ── strings, grouped by file (with tail rule) ──
  printf '\n   %s strings %s   %sROC %s%%   tail %d per file%s\n' \
    "$PILL_S" "$RST" "$DIM" "$ROC_STRINGS" "$STRING_TAIL" "$RST"
  for ft in "${FILE_TALLIES[@]}"; do
    IFS='|' read -r file _rest <<<"$ft"
    local has=0
    while IFS='|' read -r side f val rest; do
      [[ -z "$side" ]] && continue
      [[ "$side" == "__truncated__" ]] && continue
      has=1; break
    done < <(strings_for_file_tail "$file")
    [[ $has -eq 0 ]] && continue
    printf '\n     %s[%s]%s\n' "$BOLD" "$file" "$RST"
    while IFS='|' read -r side f val rest; do
      [[ -z "$side" ]] && continue
      if [[ "$side" == "__truncated__" ]]; then
        printf '       %s%s of %s hidden (showing tail %d)%s\n' "$DIM" "$f" "$val" "$STRING_TAIL" "$RST"
        continue
      fi
      local truncated="${val:0:80}"; [[ ${#val} -gt 80 ]] && truncated+="…"
      printf '       %s %s\n' "$(side_glyph "$side")" "$truncated"
    done < <(strings_for_file_tail "$file")
  done

  # ── sections ──
  printf '\n   %s sections %s   %s(empty — no binary sections in Python source)%s\n' "$PILL_E" "$RST" "$DIM" "$RST"
}

# ─────────────────────────────────────────────── prototype 6: heat map ──────
proto_6() {
  banner 6 "HEAT MAP  —  file × scope grid + drilldown" \
    "Where is change concentrated? Spatial overview, then expand the hot rows."

  printf '   %s%s → %s%s   %sROC %s%%%s\n\n' "$BOLD" "$OLD_VER" "$NEW_VER" "$RST" "$DIM" "$ROC_OVERALL" "$RST"

  printf '   %s%-26s %-9s %-9s %-9s %-9s %-9s %-9s%s\n' \
    "$DIM" "" "traits" "metrics" "kv" "symbols" "strings" "sections" "$RST"
  printf '   %s%s%s\n' "$DIM" "$(rule 90 ─)" "$RST"

  heat_cell() {
    local roc="$1"
    if (( $(echo "$roc >= 30" | bc -l) )); then
      printf '%s%-9s%s' "$HOSTILE" " ████░" "$RST"
    elif (( $(echo "$roc >= 5" | bc -l) )); then
      printf '%s%-9s%s' "$SUSPECT" " ███░░" "$RST"
    elif (( $(echo "$roc >= 1" | bc -l) )); then
      printf '%s%-9s%s' "$NOTABLE" " ██░░░" "$RST"
    elif (( $(echo "$roc > 0" | bc -l) )); then
      printf '%s%-9s%s' "$BASELN" " █░░░░" "$RST"
    else
      printf '%s%-9s%s' "$DIM" " ─" "$RST"
    fi
  }

  # Per-file ROCs as emitted by the weighted engine. The malicious files
  # now dominate; the jitter files collapse to ROC=0 across every scope.
  printf '   %-26s' "models/yolo/model.py"
  heat_cell 100.0; heat_cell 16.4; heat_cell 73.9; heat_cell 37.0; heat_cell 24.2; heat_cell 0; printf '\n'
  printf '   %-26s' "utils/downloads.py"
  heat_cell 97.1; heat_cell 6.8;  heat_cell 62.0; heat_cell 2.5; heat_cell 9.5; heat_cell 0; printf '\n'
  printf '   %-26s' "__init__.py"
  heat_cell 0;    heat_cell 0;    heat_cell 5.9;  heat_cell 0;   heat_cell 14.3; heat_cell 0; printf '\n'
  printf '   %s%-26s%s' "$DIM" "11 jitter/unchanged files (collapsed)" "$RST"
  heat_cell 0;    heat_cell 0;    heat_cell 0;    heat_cell 0;   heat_cell 0;    heat_cell 0; printf '\n'

  printf '\n   %sDRILLDOWN — models/yolo/model.py%s\n' "$BOLD" "$RST"
  printf '     %s%s%s\n' "$BOLD" "traits" "$RST"
  for rec in "${TRAITS[@]}"; do
    IFS='|' read -r side file crit id desc <<<"$rec"
    [[ "$file" != "models/yolo/model.py" ]] && continue
    [[ "$crit" == "baseline" || "$crit" == "component" ]] && continue
    local sid; sid=$(short_id "$id")
    printf '       %s %s %s\n' "$(crit_glyph "$crit")" "$(side_glyph "$side")" "$(crit_paint "$crit" "$sid")"
  done
  printf '     %s%s%s\n' "$BOLD" "kv" "$RST"
  for rec in "${KV[@]}"; do
    IFS='|' read -r side file path ov nv <<<"$rec"
    [[ "$file" != "models/yolo/model.py" ]] && continue
    if [[ "$side" == "+" ]]; then printf '       + %-36s = %s\n' "$path" "$nv"
    else printf '       ~ %-36s : %s%s → %s%s\n' "$path" "$DIM" "$ov" "$RST" "$nv"; fi
  done
  printf '     %s%s%s   %s(last %d in file)%s\n' "$BOLD" "strings" "$RST" "$DIM" "$STRING_TAIL" "$RST"
  while IFS='|' read -r side f val rest; do
    [[ -z "$side" || "$side" == "__truncated__" ]] && continue
    local truncated="${val:0:80}"; [[ ${#val} -gt 80 ]] && truncated+="…"
    printf '       %s %s\n' "$(side_glyph "$side")" "$truncated"
  done < <(strings_for_file_tail "models/yolo/model.py")
}

# ───────────────────────────────────────── prototype 7: per-file storyline ──
proto_7() {
  banner 7 "PER-FILE STORYLINE  —  per-file paragraph + scope tally" \
    "Each file gets a one-line summary. No editorial — just where things changed."

  printf '   %s%s%s   →   %s%s%s   %sROC %s%%%s\n' \
    "$BOLD" "$OLD_VER" "$RST" "$BOLD" "$NEW_VER" "$RST" "$DIM" "$ROC_OVERALL" "$RST"
  printf '   %s%s%s\n\n' "$DIM" "$(rule 60 ─)" "$RST"
  printf '   %s%d files changed · %d added · %d removed · %d unchanged%s\n\n' \
    "$DIM" "$FILES_CHANGED" "$FILES_ADDED" "$FILES_REMOVED" "$FILES_UNCHANGED" "$RST"

  for ft in "${FILE_TALLIES[@]}"; do
    IFS='|' read -r file t m k y s e <<<"$ft"
    [[ "$file" == "__init__.py" ]] && continue

    printf '   %s%s%s\n' "$BOLD" "$file" "$RST"
    printf '     %scounts:%s traits %s · metrics %s · kv %s · symbols %s · strings %s\n' \
      "$DIM" "$RST" "$t" "$m" "$k" "$y" "$s"

    # top trait additions
    local rows=""
    for rec in "${TRAITS[@]}"; do
      IFS='|' read -r side f crit id desc <<<"$rec"
      [[ "$f" == "$file" ]] && rows+="$(crit_rank "$crit")|$side|$crit|$id"$'\n'
    done
    printf '     %sleading traits:%s\n' "$DIM" "$RST"
    printf '%s' "$rows" | sort -t'|' -k1,1nr | head -3 | while IFS='|' read -r rk side crit id; do
      [[ -z "$id" ]] && continue
      local sid; sid=$(short_id "$id")
      printf '       %s %s %s\n' "$(crit_glyph "$crit")" "$(side_glyph "$side")" "$(crit_paint "$crit" "$sid")"
    done

    # new symbol imports (compact line)
    local syms=""
    for rec in "${SYMBOLS[@]}"; do
      IFS='|' read -r side f kind sym <<<"$rec"
      [[ "$f" == "$file" && "$side" == "+" ]] && syms+="$sym, "
    done
    [[ -n "$syms" ]] && printf '     %snew imports:%s %s\n' "$DIM" "$RST" "${syms%, }"

    # new kv values (top 2)
    printf '     %sleading kv:%s\n' "$DIM" "$RST"
    local kvshown=0
    for rec in "${KV[@]}"; do
      IFS='|' read -r side f path ov nv <<<"$rec"
      [[ "$f" != "$file" ]] && continue
      [[ "$side" != "+" ]] && continue
      printf '       + %-36s = %s\n' "$path" "$nv"
      kvshown=$((kvshown+1)); [[ $kvshown -ge 2 ]] && break
    done

    # new strings (last 25 — filtered to longer ones)
    printf '     %snew strings (tail %d):%s\n' "$DIM" "$STRING_TAIL" "$RST"
    while IFS='|' read -r side f val rest; do
      [[ -z "$side" || "$side" == "__truncated__" ]] && continue
      [[ "$side" != "+" ]] && continue
      local truncated="${val:0:78}"; [[ ${#val} -gt 78 ]] && truncated+="…"
      printf '       + %s\n' "$truncated"
    done < <(strings_for_file_tail "$file") | head -5

    printf '\n'
  done

  # mention the jitter and section scopes briefly
  printf '   %s(metrics/sections: rounding-noise on 9 other files; sections empty for Python.)%s\n' "$DIM" "$RST"
}

# ────────────────────────────────────────── prototype 8: per-scope histogram ─
proto_8() {
  banner 8 "PER-SCOPE HISTOGRAM  —  one stacked bar per scope, drilldown below" \
    "Top: scope-level horizontal bars by count. Below: drilldown of high-volume scopes."

  printf '   %s%s → %s%s   %sROC %s%%%s\n\n' "$BOLD" "$OLD_VER" "$NEW_VER" "$RST" "$DIM" "$ROC_OVERALL" "$RST"

  bar_for_scope() {
    local label="$1" totals="$2" roc="$3"
    IFS='|' read -r a r c old new <<<"$totals"
    local total=$((a + r + c))
    local bar=""
    local i
    # scale: 1 block per ~5 changes, cap at 30
    local blocks=$(( total / 5 ))
    (( blocks > 30 )) && blocks=30
    (( total > 0 && blocks == 0 )) && blocks=1
    for ((i=0;i<a;i+=5));  do bar+="${GRN}█${RST}"; done
    for ((i=0;i<r;i+=5));  do bar+="${RED}█${RST}"; done
    for ((i=0;i<c;i+=5));  do bar+="${YEL}█${RST}"; done
    [[ -z "$bar" ]] && bar="${DIM}─${RST}"
    printf '   %-10s %s+%3d -%3d ~%3d%s  %b  %sROC %s%%%s\n' \
      "$label" "$DIM" "$a" "$r" "$c" "$RST" "$bar" "$BOLD" "$roc" "$RST"
  }
  bar_for_scope "traits"   "$SCOPE_TRAITS_T"   "$ROC_TRAITS"
  bar_for_scope "metrics"  "$SCOPE_METRICS_T"  "$ROC_METRICS"
  bar_for_scope "kv"       "$SCOPE_KV_T"       "$ROC_KV"
  bar_for_scope "symbols"  "$SCOPE_SYMBOLS_T"  "$ROC_SYMBOLS"
  bar_for_scope "strings"  "$SCOPE_STRINGS_T"  "$ROC_STRINGS"
  bar_for_scope "sections" "$SCOPE_SECTIONS_T" "$ROC_SECTIONS"

  printf '\n   %sper-file × scope%s\n' "$BOLD" "$RST"
  for ft in "${FILE_TALLIES[@]}"; do
    IFS='|' read -r file t m k y s e <<<"$ft"
    [[ "$file" == "__init__.py" ]] && continue
    printf '     %s%-26s%s  T%s M%s K%s Y%s S%s\n' \
      "$BOLD" "$file" "$RST" "$t" "$m" "$k" "$y" "$s"
  done

  printf '\n   %sdrilldown — non-baseline traits + new symbols%s\n' "$BOLD" "$RST"
  for rec in "${TRAITS[@]}"; do
    IFS='|' read -r side file crit id desc <<<"$rec"
    [[ "$crit" == "baseline" || "$crit" == "component" ]] && continue
    local sid; sid=$(short_id "$id")
    printf '     %s %s %s%-46s%s %s%s%s\n' \
      "$(crit_glyph "$crit")" "$(side_glyph "$side")" "$([[ "$crit" == "suspicious" ]] && echo "$BOLD")" "$sid" "$RST" "$DIM" "$file" "$RST"
  done
  printf '     %s· %d baseline/component traits collapsed%s\n' "$DIM" \
    "$(printf '%s\n' "${TRAITS[@]}" | awk -F'|' '$3=="baseline" || $3=="component"' | wc -l | tr -d ' ')" "$RST"
}

# ─────────────────────────────────────── prototype 9: per-file changelog ────
proto_9() {
  banner 9 "PER-FILE CHANGELOG  —  framed card per file, scopes inside" \
    "One card per non-jitter file. Each card lists changes per scope, no verdict text."

  card_for_file() {
    local file="$1" tally="$2"
    IFS='|' read -r _ t m k y s e <<<"$tally"
    local W=$((COLS-6))
    local meta="traits $t  metrics $m  kv $k  symbols $y  strings $s"

    printf '   %s┌─%s %s%s%s %s\n' "$DIM" "$RST" "$BOLD" "$file" "$DIM" "$(rule $((COLS-${#file}-7)) ─)$RST"
    printf '   %s│%s  %s%s%s\n' "$DIM" "$RST" "$ITAL$DIM" "$meta" "$RST"
    printf '   %s├%s%s\n' "$DIM" "$(rule $((COLS-3)) ─)" "$RST"

    # traits (only non-baseline)
    printf '   %s│%s  %s%s%s\n' "$DIM" "$RST" "$BOLD" "traits" "$RST"
    for rec in "${TRAITS[@]}"; do
      IFS='|' read -r side f crit id desc <<<"$rec"
      [[ "$f" != "$file" ]] && continue
      [[ "$crit" == "baseline" || "$crit" == "component" ]] && continue
      local sid; sid=$(short_id "$id")
      printf '   %s│%s    %s %s %s\n' "$DIM" "$RST" "$(crit_glyph "$crit")" "$(side_glyph "$side")" "$(crit_paint "$crit" "$sid")"
    done

    # metrics (top 4)
    printf '   %s│%s  %s%s%s\n' "$DIM" "$RST" "$BOLD" "metrics" "$RST"
    local mc=0
    for rec in "${METRICS[@]}"; do
      IFS='|' read -r side f path ov nv <<<"$rec"
      [[ "$f" != "$file" ]] && continue
      mc=$((mc+1)); [[ $mc -gt 4 ]] && break
      if [[ "$side" == "+" ]]; then printf '   %s│%s    + %-36s = %s\n' "$DIM" "$RST" "$path" "$nv"
      else printf '   %s│%s    ~ %-36s : %s → %s\n' "$DIM" "$RST" "$path" "$ov" "$nv"; fi
    done

    # kv (top 4)
    printf '   %s│%s  %s%s%s\n' "$DIM" "$RST" "$BOLD" "kv" "$RST"
    local kc=0
    for rec in "${KV[@]}"; do
      IFS='|' read -r side f path ov nv <<<"$rec"
      [[ "$f" != "$file" ]] && continue
      kc=$((kc+1)); [[ $kc -gt 4 ]] && break
      if [[ "$side" == "+" ]]; then printf '   %s│%s    + %-36s = %s\n' "$DIM" "$RST" "$path" "$nv"
      else printf '   %s│%s    ~ %-36s : %s → %s\n' "$DIM" "$RST" "$path" "$ov" "$nv"; fi
    done

    # symbols
    printf '   %s│%s  %s%s%s\n' "$DIM" "$RST" "$BOLD" "symbols" "$RST"
    for rec in "${SYMBOLS[@]}"; do
      IFS='|' read -r side f kind sym <<<"$rec"
      [[ "$f" != "$file" ]] && continue
      printf '   %s│%s    %s [%s] %s\n' "$DIM" "$RST" "$(side_glyph "$side")" "$kind" "$sym"
    done

    # strings (last 25)
    printf '   %s│%s  %s%s%s   %s(last %d in file)%s\n' "$DIM" "$RST" "$BOLD" "strings" "$RST" "$DIM" "$STRING_TAIL" "$RST"
    while IFS='|' read -r side f val rest; do
      [[ -z "$side" ]] && continue
      if [[ "$side" == "__truncated__" ]]; then
        printf '   %s│%s    %s%s of %s hidden%s\n' "$DIM" "$RST" "$DIM" "$f" "$val" "$RST"
        continue
      fi
      local truncated="${val:0:75}"; [[ ${#val} -gt 75 ]] && truncated+="…"
      printf '   %s│%s    %s %s\n' "$DIM" "$RST" "$(side_glyph "$side")" "$truncated"
    done < <(strings_for_file_tail "$file")

    # sections
    printf '   %s│%s  %s%s%s   %s(empty)%s\n' "$DIM" "$RST" "$BOLD" "sections" "$RST" "$DIM" "$RST"
    printf '   %s└%s%s\n\n' "$DIM" "$(rule $((COLS-3)) ─)" "$RST"
  }

  for tally in "${FILE_TALLIES[@]}"; do
    IFS='|' read -r file _rest <<<"$tally"
    [[ "$file" == "__init__.py" ]] && continue
    card_for_file "$file" "$tally"
  done
  printf '   %s9 metric-jitter files collapsed; 3 unchanged files omitted%s\n' "$DIM" "$RST"
}

# ────────────────────────────────────────── prototype 10: terse per-file ────
proto_10() {
  banner 10 "TERSE PER-FILE  —  single-character verbs, all scopes inline" \
    "Densest per-file form. !=non-baseline trait, +=add, -=remove, ~=changed."

  printf '   %s%s → %s%s   %sROC %s%%%s\n\n' "$BOLD" "$OLD_VER" "$NEW_VER" "$RST" "$DIM" "$ROC_OVERALL" "$RST"

  per_file() {
    local file="$1" tally="$2"
    IFS='|' read -r _ t m k y s e <<<"$tally"
    printf '   %s%s%s   %s· traits %s · metrics %s · kv %s · symbols %s · strings %s%s\n' \
      "$BOLD" "$file" "$RST" "$DIM" "$t" "$m" "$k" "$y" "$s" "$RST"

    # traits (above-baseline)
    for rec in "${TRAITS[@]}"; do
      IFS='|' read -r side f crit id desc <<<"$rec"
      [[ "$f" != "$file" ]] && continue
      [[ "$crit" == "baseline" || "$crit" == "component" ]] && continue
      local sid; sid=$(short_id "$id")
      local marker
      case "$crit/$side" in
        suspicious/+) marker="${HOSTILE}!${RST}" ;;
        */+) marker="${GRN}+${RST}" ;;
        */-) marker="${RED}-${RST}" ;;
        *)   marker=" " ;;
      esac
      local note=""
      [[ -n "$desc" ]] && note="${DIM}  # $desc${RST}"
      printf '       %b  %s %s%-44s%s%b\n' "$marker" "T" "$([[ "$crit" == "suspicious" ]] && echo "$BOLD$SUSPECT")" "$sid" "$RST" "$note"
    done

    # metrics (changed, top 3)
    local mc=0
    for rec in "${METRICS[@]}"; do
      IFS='|' read -r side f path ov nv <<<"$rec"
      [[ "$f" != "$file" ]] && continue
      [[ "$side" != "~" && "$side" != "+" ]] && continue
      mc=$((mc+1)); [[ $mc -gt 3 ]] && break
      if [[ "$side" == "+" ]]; then
        printf '       %s%s%s  M %-36s = %s\n' "$GRN" "+" "$RST" "$path" "$nv"
      else
        printf '       %s%s%s  M %-36s : %s%s%s → %s\n' "$YEL" "~" "$RST" "$path" "$DIM" "$ov" "$RST" "$nv"
      fi
    done

    # kv (top 3)
    local kc=0
    for rec in "${KV[@]}"; do
      IFS='|' read -r side f path ov nv <<<"$rec"
      [[ "$f" != "$file" ]] && continue
      kc=$((kc+1)); [[ $kc -gt 3 ]] && break
      if [[ "$side" == "+" ]]; then
        printf '       %s%s%s  K %-36s = %s\n' "$GRN" "+" "$RST" "$path" "$nv"
      else
        printf '       %s%s%s  K %-36s : %s%s%s → %s\n' "$YEL" "~" "$RST" "$path" "$DIM" "$ov" "$RST" "$nv"
      fi
    done

    # symbols (added)
    for rec in "${SYMBOLS[@]}"; do
      IFS='|' read -r side f kind sym <<<"$rec"
      [[ "$f" != "$file" ]] && continue
      printf '       %s%s%s  Y [%s] %s\n' "$GRN" "$side" "$RST" "$kind" "$sym"
    done

    # strings (last 25)
    while IFS='|' read -r side f val rest; do
      [[ -z "$side" ]] && continue
      if [[ "$side" == "__truncated__" ]]; then
        printf '       %s   S … %s of %s hidden (showing tail %d)%s\n' "$DIM" "$f" "$val" "$STRING_TAIL" "$RST"
        continue
      fi
      local truncated="${val:0:70}"; [[ ${#val} -gt 70 ]] && truncated+="…"
      printf '       %s%s%s  S %s\n' "$([[ "$side" == "+" ]] && echo "$GRN" || echo "$RED")" "$side" "$RST" "$truncated"
    done < <(strings_for_file_tail "$file")

    printf '\n'
  }

  for tally in "${FILE_TALLIES[@]}"; do
    IFS='|' read -r file _rest <<<"$tally"
    [[ "$file" == "__init__.py" ]] && continue
    per_file "$file" "$tally"
  done
  printf '   %s9 metric-jitter files + 3 unchanged collapsed%s\n' "$DIM" "$RST"
}

# ───────────────────────────────────────────────────── design notes / footer ─
notes() {
  printf '\n%s%s%s\n' "$DIM" "$(rule)" "$RST"
  printf '%sDESIGN NOTES%s\n' "$BOLD" "$RST"
  printf '%s%s%s\n\n' "$DIM" "$(rule)" "$RST"
  cat <<EOF
   Cleave's diff command surfaces evidence neutrally. Verdict-shaped framing
   (e.g. "supply-chain attack detected") is a downstream concern (litmus).
   Each prototype renders all six scopes — traits, metrics, kv, symbols,
   strings, sections — and follows the same rule for the strings scope:
   show only the last ${STRING_TAIL} entries per file (malware tends to append).

   ${BOLD}Trade-off matrix${RST}

       view              best when               worst when
   1   scope headline    triaging fast           you want the data, not summary
   2   per-file pane     reviewing 1–3 files     >3 files; vertical noise
   3   change ribbon     scanning by scope       care about per-file context
   4   scoreboard        comparing volumes       you want detail
   5   scope-section     auditing rules          a finding spans many sections
   6   heat map          finding hotspots        single-file diffs
   7   per-file story    writing a ticket        terminal piping
   8   stacked-bar hist  numeric-first eye       care about identity
   9   per-file card     screenshots, reports    routine CLI use
  10   terse per-file    daily driver            single-file forensics

   ${BOLD}Recommended composition${RST}

   • ${YEL}Default${RST} (\`cleave diff old new\`):   #1 (scope rollup) + #10 (per-file
     terse). Top-of-screen tells you what changed in volume; the per-file
     listing under it tells you what specifically changed.

   • ${YEL}--by-scope${RST}:   #5 (scope-as-section). For people auditing rule
     coverage; six headers, taxonomy groups inside.

   • ${YEL}--by-file${RST}:    #9 (per-file card). For incident reports and
     screenshots — one frame per file, all scopes inside.

   • ${YEL}--narrative${RST}:  #7. For pasting into a Slack channel or ticket.

   ${BOLD}Avoid as default${RST}

   • #2: paneled-per-file is too tall for >2 changed files.
   • #3: change-ribbon hides per-file co-occurrence.
   • #6: heat map is striking but takes a 2-pass read.
EOF
}

# ─────────────────────────────────────────────────────────── dispatcher ─────
usage() {
  cat <<EOF
Usage: $0 [N ...]   render specific prototypes (1..10)
       $0           render all 10 + design notes
       $0 notes     just print the design-notes summary
EOF
}

main() {
  if [[ $# -eq 1 && "$1" == "notes" ]]; then notes; return 0; fi
  if [[ $# -ge 1 ]] && [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then usage; return 0; fi

  local picks
  if [[ $# -eq 0 ]]; then
    picks=(1 2 3 4 5 6 7 8 9 10)
  else
    picks=("$@")
  fi

  for n in "${picks[@]}"; do
    case "$n" in
      1)  proto_1 ;; 2)  proto_2 ;; 3)  proto_3 ;; 4)  proto_4 ;; 5)  proto_5 ;;
      6)  proto_6 ;; 7)  proto_7 ;; 8)  proto_8 ;; 9)  proto_9 ;; 10) proto_10 ;;
      *)  printf '%sno such prototype: %s%s\n' "$RED" "$n" "$RST" >&2 ;;
    esac
  done

  [[ $# -eq 0 ]] && notes
}

main "$@"
