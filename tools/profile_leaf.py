#!/usr/bin/env python3
"""Leaf (exclusive) time hotspots from samply profile JSON."""
import bisect, gzip, json, subprocess, sys
from collections import defaultdict

BINARY = "out/cleave.bench"
NOISE = {"__psynch_cvwait", "kevent", "mach_msg", "__semwait_signal", "poll", "read", "write", "sleep",
         "_kevent", "_read", "_write", "_mach_msg", "_mach_msg2_trap", "_mach_msg_trap", "_pthread_cond_wait",
         "___pthread_cond_wait", "__ulock_wait", "__workq_kernreturn"}

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
    profile_path = sys.argv[1] if len(sys.argv) > 1 else "out/bench.profile.json.gz"
    base = "/Users/t/dev/atomdrift/cleave"
    syms = load_symbols(f"{base}/{BINARY}")
    sym_addrs = [s[0] for s in syms]

    with gzip.open(f"{base}/{profile_path}") as f:
        profile = json.load(f)

    cleave_pid = next(t["pid"] for t in profile["threads"] if t["name"] != "rizin")
    leaf_counts, total = defaultdict(int), 0

    for thread in (t for t in profile["threads"] if t["pid"] == cleave_pid):
        rt = thread["resourceTable"]
        res_names = [thread["stringArray"][i] if i is not None else None for i in rt["name"]]
        res_idx = next((i for i, n in enumerate(res_names) if n == "cleave.bench"), None)
        if res_idx is None:
            continue
        func_res, frame_func, frame_addr = thread["funcTable"]["resource"], thread["frameTable"]["func"], thread["frameTable"]["address"]
        stack_frame, stack_prefix = thread["stackTable"]["frame"], thread["stackTable"]["prefix"]
        frame_sym = {}
        string_array = thread["stringArray"]
        func_name = thread["funcTable"]["name"]
        for fi, (fni, addr) in enumerate(zip(frame_func, frame_addr)):
            if func_res[fni] == res_idx and addr >= 0:
                i = bisect.bisect_right(sym_addrs, addr) - 1
                if i >= 0:
                    frame_sym[fi] = simplify(syms[i][1])
            else:
                name_idx = func_name[fni]
                if name_idx is not None:
                    frame_sym[fi] = string_array[name_idx]
        for stack_idx in thread["samples"]["stack"]:
            if stack_idx is None:
                continue
            total += 1
            # Walk up to find leaf (deepest) cleave frame
            cur = stack_idx
            leaf_name = None
            while cur is not None:
                fi = stack_frame[cur]
                name = frame_sym.get(fi)
                if name and name not in NOISE:
                    if leaf_name is None:
                        leaf_name = name
                    break
                cur = stack_prefix[cur]
            if leaf_name:
                leaf_counts[leaf_name] += 1

    ranked = sorted(leaf_counts.items(), key=lambda x: -x[1])
    print(f"Total samples: {total}\n")
    print(f"{'Samples':>8}  {'%':>6}  Function (leaf)")
    print("-" * 120)
    for name, c in ranked[:50]:
        print(f"{c:>8}  {100*c/total:>5.2f}%  {name}")

if __name__ == "__main__":
    main()
