#!/usr/bin/env python3
"""Find who calls a given function in a samply profile."""
import bisect, gzip, json, subprocess, sys
from collections import defaultdict

BINARY = "out/cleave.bench"

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
    profile_path = sys.argv[1]
    target_substr = sys.argv[2]
    base = "/Users/t/dev/atomdrift/cleave"
    syms = load_symbols(f"{base}/{BINARY}")
    sym_addrs = [s[0] for s in syms]

    with gzip.open(profile_path) as f:
        profile = json.load(f)

    cleave_pid = next(t["pid"] for t in profile["threads"] if t["name"] != "rizin")
    caller_counts = defaultdict(int)
    total_hits = 0

    for thread in (t for t in profile["threads"] if t["pid"] == cleave_pid):
        rt = thread["resourceTable"]
        res_names = [thread["stringArray"][i] if i is not None else None for i in rt["name"]]
        func_res = thread["funcTable"]["resource"]
        frame_func, frame_addr = thread["frameTable"]["func"], thread["frameTable"]["address"]
        stack_frame, stack_prefix = thread["stackTable"]["frame"], thread["stackTable"]["prefix"]
        string_array = thread["stringArray"]
        func_name_idx = thread["funcTable"]["name"]

        frame_sym = {}
        for fi, (fni, addr) in enumerate(zip(frame_func, frame_addr)):
            res_idx = func_res[fni]
            res_name = res_names[res_idx] if res_idx is not None else None
            if res_name == "cleave.bench" and addr >= 0:
                i = bisect.bisect_right(sym_addrs, addr) - 1
                if i >= 0:
                    frame_sym[fi] = simplify(syms[i][1])
            else:
                # External symbol from runtime or library
                name_idx = func_name_idx[fni]
                if name_idx is not None:
                    frame_sym[fi] = string_array[name_idx]

        # Walk stacks; for each stack containing the target, count immediate parent
        for stack_idx in thread["samples"]["stack"]:
            if stack_idx is None:
                continue
            cur = stack_idx
            prev_name = None
            while cur is not None:
                fi = stack_frame[cur]
                name = frame_sym.get(fi)
                if name and target_substr in name:
                    total_hits += 1
                    # Walk up one more frame to find the caller (non-target)
                    caller = stack_prefix[cur]
                    while caller is not None:
                        cfi = stack_frame[caller]
                        cname = frame_sym.get(cfi)
                        if cname and target_substr not in cname:
                            caller_counts[cname] += 1
                            break
                        caller = stack_prefix[caller]
                    break
                cur = stack_prefix[cur]

    ranked = sorted(caller_counts.items(), key=lambda x: -x[1])
    print(f"Target: functions containing {target_substr!r}")
    print(f"Total samples hitting target: {total_hits}\n")
    print(f"{'Samples':>8}  {'%':>6}  Caller")
    print("-" * 120)
    for name, c in ranked[:30]:
        print(f"{c:>8}  {100*c/total_hits:>5.2f}%  {name}")

if __name__ == "__main__":
    main()
