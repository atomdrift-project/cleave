#!/bin/sh
# Repository hygiene checks run by `make lint`.
#
#   1. No non-test Rust source file over 2,000 lines.
#   2. No names of internal projects or personal paths in tracked files.
#   3. Rule IDs hard-coded in the validators may only shrink: an exemption
#      belongs on the rule (`exempt:` in its YAML), not in the engine.
set -eu
cd "$(dirname "$0")/.."
status=0

# 1. File length. The reviewed-exemption table is listed until its entries
#    move into the trait corpus as `exempt:` fields.
MAX_LINES=2000
LONG_FILE_ALLOWLIST="src/capabilities/validation/taxonomy/reviewed.rs"
for f in $(git ls-files --cached --others --exclude-standard -- 'src/*.rs' 'crates/*.rs' | sort -u); do
    [ -f "$f" ] || continue
    case "$f" in
        */tests/*|*/tests.rs|*_test.rs|*_tests.rs) continue ;;
    esac
    case " $LONG_FILE_ALLOWLIST " in *" $f "*) continue ;; esac
    lines=$(wc -l < "$f")
    if [ "$lines" -gt "$MAX_LINES" ]; then
        echo "error: $f has $lines lines (limit $MAX_LINES); split it into modules" >&2
        status=1
    fi
done

# 2. Internal names. Contributors cannot see these projects, so references to
#    them in code, docs or tests explain nothing.
# tools/model_facts_manifest*.py read a model checkout by its name on purpose.
PRIVATE='\b(litmus|hopper|isomer|atomscan|postdoc|gauntlet|collimator|cyclotron|cleave-tuna|beamline)\b|/Users/t/|traits-dev'
if git ls-files -- ':!testdata' ':!tests/fixtures' ':!tests/data' ':!tests/yara_tier_fixtures' \
        ':!scripts/check-hygiene.sh' ':!*.json' ':!release.mk' ':!tools/model_facts_manifest.py' \
        ':!tools/test_model_facts_manifest.py' \
    | xargs grep -nIiE "$PRIVATE" -- 2>/dev/null \
    | grep -v '/Users/x/traits-dev'; then
    echo "error: internal project names or personal paths above" >&2
    status=1
fi

# 3. Rule IDs in the validators. Lower RULE_ID_BUDGET as exemptions move out.
#    emitted.rs is the catalogue of ids the engine itself emits, not exemptions.
#    `sort -u`: during a merge conflict git lists a file once per stage.
RULE_ID_BUDGET=469
count=$(git ls-files --cached --others --exclude-standard -- 'src/capabilities/validation/*.rs' \
    | sort -u \
    | grep -vE '(^|/)tests?(/|\.rs$)|_tests?\.rs$|/emitted\.rs$' \
    | xargs grep -ohE '"[a-z-]+/[a-z0-9/_.-]+::[a-z0-9_.-]+"' -- 2>/dev/null | wc -l)
if [ "$count" -gt "$RULE_ID_BUDGET" ]; then
    echo "error: $count rule IDs hard-coded in src/capabilities/validation (budget $RULE_ID_BUDGET)." >&2
    echo "       Put the exemption on the rule as an \`exempt:\` entry instead." >&2
    status=1
fi

exit $status
