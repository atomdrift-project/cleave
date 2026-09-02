#!/usr/bin/env python3
"""Regenerate the bigram table in src/random_validator.rs.

Emits log10 P(next | prev) over 28 symbols (start marker, a-z, end marker)
with add-one smoothing, from English prose.

The corpus is deliberately local and reproducible rather than downloaded: the
prose in the repository docs plus every `desc:` line in the cleave-traits rule
set, which together are ~555k words of ordinary English. A larger or more
general corpus would be an improvement -- particularly one carrying names from
more languages, since the current model penalises consonant-dense ones (see
the Limits section in random_validator.rs).

    python3 scripts/gen_bigram_table.py ../traits-dev . > /tmp/table.rs

then paste the rows into BIGRAM_LOGP.
"""
import collections
import glob
import math
import re
import sys

SYM = "^abcdefghijklmnopqrstuvwxyz$"
K = 1.0


def corpus_words(roots):
    text = []
    for root in roots:
        for path in glob.glob(f"{root}/*.md") + glob.glob(f"{root}/docs/*.md"):
            try:
                text.append(open(path, encoding="utf-8", errors="ignore").read())
            except OSError:
                pass
        for path in glob.glob(f"{root}/**/*.yaml", recursive=True):
            try:
                for line in open(path, encoding="utf-8", errors="ignore"):
                    m = re.match(r"\s*#?\s*desc:\s*(.+)", line)
                    if m:
                        text.append(m.group(1))
            except OSError:
                pass
    return [w.lower() for w in re.findall(r"[A-Za-z]{2,}", " ".join(text))]


def main():
    words = corpus_words(sys.argv[1:] or ["."])
    big, first = collections.Counter(), collections.Counter()
    for w in words:
        t = f"^{w}$"
        for a, b in zip(t, t[1:]):
            big[a + b] += 1
            first[a] += 1
    print(f"// {len(words)} words / {len(big)} distinct bigrams", file=sys.stderr)
    for a in SYM:
        row = [
            math.log10((big.get(a + b, 0) + K) / (first.get(a, 0) + K * len(SYM)))
            for b in SYM
        ]
        label = {"^": "START", "$": "END"}.get(a, a)
        print(f"    // {label}")
        print("    [" + ", ".join(f"{v:.3f}" for v in row) + "],")


if __name__ == "__main__":
    main()
