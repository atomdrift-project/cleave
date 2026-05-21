#!/usr/bin/env python3
"""For stacks that hit lock_exclusive_slow via 0xc88, find the cleave caller."""
import bisect, gzip, json, subprocess, sys
from collections import Counter

BINARY = "out/cleave.bench"

def load_symbols(binary):
    out = subprocess.check_output(["nm", "-n", "--demangle", binary], stderr=subprocess.DEVNULL, text=True)
    syms = [(int(p[0], 16) - 0x100000000, p[2]) for line in out.splitlines()
            if len(p := line.split(None, 2)) == 3 and p[1] in ("t", "T")]
    return syms

def simplify(n):
    if "::" in n:
        parts = n.rsplit("::", 1)
        if len(parts[1]) == 17 and parts[1][0] == "h":
            n = parts[0]
    return n

def main():
    profile_path = sys.argv[1]
    target_substr = sys.argv[2]  # e.g. "lock_exclusive_slow"
    base = "/Users/t/dev/atomdrift/cleave"
    syms = load_symbols(f"{base}/{BINARY}")
    sym_addrs = [s[0] for s in syms]

    with gzip.open(profile_path) as f:
        profile = json.load(f)

    cleave_caller_counts = Counter()
    total = 0

    for thread in profile["threads"]:
        if thread["name"] == "rizin":
            continue
        rt = thread["resourceTable"]
        res_names = [thread["stringArray"][i] if i is not None else None for i in rt["name"]]
        func_res = thread["funcTable"]["resource"]
        frame_func, frame_addr = thread["frameTable"]["func"], thread["frameTable"]["address"]
        stack_frame, stack_prefix = thread["stackTable"]["frame"], thread["stackTable"]["prefix"]
        string_array = thread["stringArray"]
        func_name_idx = thread["funcTable"]["name"]

        frame_sym = {}
        frame_is_cleave = {}
        for fi, (fni, addr) in enumerate(zip(frame_func, frame_addr)):
            res_idx = func_res[fni]
            res_name = res_names[res_idx] if res_idx is not None else None
            if res_name == "cleave.bench" and addr >= 0:
                i = bisect.bisect_right(sym_addrs, addr) - 1
                if i >= 0:
                    frame_sym[fi] = simplify(syms[i][1])
                    frame_is_cleave[fi] = True
            else:
                name_idx = func_name_idx[fni]
                if name_idx is not None:
                    fname = string_array[name_idx]
                    frame_sym[fi] = fname
                    frame_is_cleave[fi] = False

        for stack_idx in thread["samples"]["stack"]:
            if stack_idx is None:
                continue
            # Look for target (lock_exclusive_slow) in the stack
            cur = stack_idx
            hit_found = False
            while cur is not None:
                fi = stack_frame[cur]
                name = frame_sym.get(fi, "")
                if target_substr in name:
                    hit_found = True
                    # Walk up to find first cleave function that isn't lock-internal
                    p = stack_prefix[cur]
                    cleave_caller = None
                    while p is not None:
                        cfi = stack_frame[p]
                        sname = frame_sym.get(cfi, "")
                        if frame_is_cleave.get(cfi, False) and "lock" not in sname.lower() and "parking" not in sname.lower() and "raw_rwlock" not in sname.lower():
                            cleave_caller = sname
                            break
                        p = stack_prefix[p]
                    if cleave_caller:
                        cleave_caller_counts[cleave_caller] += 1
                        total += 1
                    break
                cur = stack_prefix[cur]

    print(f"Stacks containing '{target_substr}' with resolved cleave caller: {total}\n")
    print(f"{'Samples':>8}  {'%':>6}  Cleave caller (above {target_substr})")
    print("-" * 100)
    for name, c in cleave_caller_counts.most_common(20):
        print(f"{c:>8}  {100*c/total:>5.2f}%  {name}")

if __name__ == "__main__":
    main()
