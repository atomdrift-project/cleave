#!/usr/bin/env python3
"""Symbolize a jemalloc heap dump (heap_v2) on macOS, where jeprof's addr2line
path does not work. Uses `nm -n --demangle` + address bisect, the same trick as
cleave/tools/profile_*.py, and reads the binary's load address out of the dump's
own MAPPED_LIBRARIES section to undo ASLR.

Reports LIVE bytes (curbytes) attributed two ways:
  - RETAINER: the deepest application frame in each stack (who allocated it)
  - INCLUSIVE: every distinct app frame in the stack (who is responsible for it)

Usage: heap_sym.py <heap-file> <binary> [top_n]
"""
import bisect, math, re, subprocess, sys
from collections import defaultdict


def load_symbols(binary):
    out = subprocess.check_output(
        ["nm", "-n", "--demangle", binary], stderr=subprocess.DEVNULL, text=True
    )
    syms = []
    for line in out.splitlines():
        p = line.split(None, 2)
        if len(p) == 3 and p[1] in ("t", "T"):
            try:
                syms.append((int(p[0], 16), p[2]))
            except ValueError:
                pass
    syms.sort()
    return syms


def simplify(name):
    # strip rustc hash suffix ::h0123456789abcdef
    if "::" in name:
        head, tail = name.rsplit("::", 1)
        if len(tail) == 17 and tail[0] == "h":
            name = head
    return name


APP = re.compile(r"^_?(cleave|scan|atomdrift|stng|filefacts|fletch)")


def main():
    heap_path, binary = sys.argv[1], sys.argv[2]
    top_n = int(sys.argv[3]) if len(sys.argv) > 3 else 25

    syms = load_symbols(binary)
    addrs = [s[0] for s in syms]

    text = open(heap_path).read()

    # Binary load base from the dump itself -> ASLR slide vs nm's addresses.
    m = re.search(r"^([0-9a-f]+)-[0-9a-f]+: .*" + re.escape(binary.split("/")[-1]),
                  text, re.M)
    load_base = int(m.group(1), 16) if m else 0x100000000
    nm_base = addrs[0] & ~0xFFFFFF if addrs else 0x100000000
    slide = load_base - 0x100000000

    def sym_for(a):
        a -= slide
        i = bisect.bisect_right(addrs, a) - 1
        if i < 0:
            return None
        return simplify(syms[i][1])

    retainer = defaultdict(float)
    inclusive = defaultdict(float)
    total = 0.0

    # jemalloc samples ~1 allocation per `interval` bytes, so a recorded sample
    # stands for more bytes than it holds — and the smaller the object, the
    # larger the multiplier. Without this correction the profile is biased
    # toward big allocations (a 128 MB stacker segment is always sampled; a
    # 200-byte String almost never is). Same estimator jeprof applies.
    interval = int(re.match(r"heap_v2/(\d+)", text).group(1))

    def unsample(objs, curbytes):
        if objs == 0 or curbytes == 0:
            return 0.0
        mean = curbytes / objs
        return curbytes / (1.0 - math.exp(-mean / interval))

    # "@ 0x.. 0x..\n  t*: objs: bytes [..]"
    for stack_line, count_line in re.findall(
        r"^@((?: 0x[0-9a-f]+)+)\n\s*t\*: (\d+: \d+) \[", text, re.M
    ):
        objs, raw = (int(x) for x in count_line.split(": "))
        curbytes = unsample(objs, raw)
        if curbytes == 0:
            continue
        total += curbytes
        frames = [int(a, 16) for a in stack_line.split()]
        names = [sym_for(a) for a in frames]
        app = [n for n in names if n and APP.match(n)]
        if app:
            retainer[app[0]] += curbytes
        else:
            first = next((n for n in names if n), "<unresolved>")
            retainer[f"[non-app] {first}"] += curbytes
        for n in dict.fromkeys(app):  # distinct, order-preserving
            inclusive[n] += curbytes

    mb = 1024 * 1024
    print(f"live heap in dump: {total/mb:,.0f} MB   (slide 0x{slide:x})\n")
    print("=== RETAINER (deepest app frame that allocated the live bytes) ===")
    for name, b in sorted(retainer.items(), key=lambda kv: -kv[1])[:top_n]:
        print(f"{b/mb:9,.0f} MB  {100*b/total:5.1f}%  {name[:110]}")
    print("\n=== INCLUSIVE (any app frame on the stack) ===")
    for name, b in sorted(inclusive.items(), key=lambda kv: -kv[1])[:top_n]:
        print(f"{b/mb:9,.0f} MB  {100*b/total:5.1f}%  {name[:110]}")


if __name__ == "__main__":
    main()
