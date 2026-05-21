#!/usr/bin/env python3
"""Find CPU hotspots in a samply/Firefox profiler JSON for the cleave binary."""
import bisect, gzip, json, subprocess, sys
from collections import defaultdict

BINARY = "out/cleave.bench"
PROFILE = "out/bench.profile.json.gz"
NOISE = {"__psynch_cvwait", "kevent", "mach_msg", "__semwait_signal", "poll", "read", "write", "sleep"}

def load_symbols(binary):
    out = subprocess.check_output(["nm", "-n", "--demangle", binary], stderr=subprocess.DEVNULL, text=True)
    syms = [(int(p[0], 16) - 0x100000000, p[2]) for line in out.splitlines()
            if len(p := line.split(None, 2)) == 3 and p[1] in ("t", "T")]
    return syms

def simplify(name):
    if "::" in name:
        parts = name.rsplit("::", 1)
        if len(parts[1]) == 17 and parts[1][0] == "h" and all(c in "0123456789abcdef" for c in parts[1][1:]):
            name = parts[0]
    return name

def main():
    base = sys.argv[1] if len(sys.argv) > 1 else "/Users/t/dev/atomdrift/cleave"
    syms = load_symbols(f"{base}/{BINARY}")
    sym_addrs = [s[0] for s in syms]

    with gzip.open(f"{base}/{PROFILE}") as f:
        profile = json.load(f)

    cleave_pid = next(t["pid"] for t in profile["threads"] if t["name"] != "rizin")
    counts, total = defaultdict(int), 0

    for thread in (t for t in profile["threads"] if t["pid"] == cleave_pid):
        rt = thread["resourceTable"]
        res_names = [thread["stringArray"][i] if i is not None else None for i in rt["name"]]
        res_idx = next((i for i, n in enumerate(res_names) if n == "cleave.bench"), None)
        if res_idx is None:
            continue
        func_res, frame_func, frame_addr = thread["funcTable"]["resource"], thread["frameTable"]["func"], thread["frameTable"]["address"]
        stack_frame, stack_prefix = thread["stackTable"]["frame"], thread["stackTable"]["prefix"]
        frame_sym = {}
        for fi, (fni, addr) in enumerate(zip(frame_func, frame_addr)):
            if func_res[fni] == res_idx:
                i = bisect.bisect_right(sym_addrs, addr) - 1
                if i >= 0:
                    frame_sym[fi] = simplify(syms[i][1])
        for stack_idx in thread["samples"]["stack"]:
            if stack_idx is None:
                continue
            total += 1
            seen, cur = set(), stack_idx
            while cur is not None:
                fi = stack_frame[cur]
                name = frame_sym.get(fi)
                if name and name not in seen:
                    seen.add(name)
                    counts[name] += 1
                cur = stack_prefix[cur]

    ranked = sorted(((n, c) for n, c in counts.items() if n not in NOISE), key=lambda x: -x[1])
    print(f"Total samples (cleave threads): {total}\n")
    print(f"{'Samples':>8}  {'%':>6}  Function")
    print("-" * 120)
    for name, c in ranked[:40]:
        print(f"{c:>8}  {100*c/total:>5.1f}%  {name}")

if __name__ == "__main__":
    main()
