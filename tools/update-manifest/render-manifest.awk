# Render versions.toml from two tab-separated source-of-truth files.
#
# The manifest is GENERATED output; these TSVs are the state. Keeping them
# separate mirrors the design: an immutable artifact catalog + mutable pointers.
#
#   artifacts.tsv:  key \t file \t sha256 \t commit \t date     (append-only catalog)
#   pointers.tsv:   release \t channel \t key                   (current pointers)
#
# Both MUST be pre-sorted by the caller (artifacts by key; pointers by channel
# then release) so output is deterministic without relying on awk sort, which
# BWK awk (macOS) lacks. Output order follows input order.
#
# Usage:
#   sort artifacts.tsv | ... ; sort pointers.tsv | ...
#   awk -v vu="2026-06-09T00:00:00Z" -f render-manifest.awk artifacts.tsv pointers.tsv

BEGIN {
    FS = "\t"
    fileidx = 0
    print "manifest_version = 1"
    print "valid_until      = " vu
    print ""
}

# Distinguish the two inputs by ARGUMENT ORDER, not filename: arg 1 is the
# artifact catalog, arg 2 is the pointers. Robust to whatever the caller names
# its temp files.
FNR == 1 { fileidx++ }

# First file: the artifact catalog. One [artifacts.<key>] block each.
fileidx == 1 {
    if (NF < 5) next
    print "[artifacts." $1 "]"
    print "file   = \"" $2 "\""
    print "sha256 = \"" $3 "\""
    print "commit = \"" $4 "\""
    print "date   = \"" $5 "\""
    print ""
    next
}

# Second file: pointers, grouped into one [<channel>] table per channel.
fileidx == 2 {
    if (NF < 3) next
    if ($2 != curchan) {
        if (curchan != "") print ""
        curchan = $2
        print "[" $2 "]"
    }
    print "\"" $1 "\" = \"" $3 "\""
}
