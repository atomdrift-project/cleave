#!/usr/bin/env python3
"""Find callers of a given hex address leaf across all threads."""
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
    target_addr = int(sys.argv[2], 16)
    base = "/Users/t/dev/atomdrift/cleave"
    syms = load_symbols(f"{base}/{BINARY}")
    sym_addrs = [s[0] for s in syms]

    with gzip.open(profile_path) as f:
        profile = json.load(f)

    caller_counts = Counter()
    caller_2 = Counter()
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
        for fi, (fni, addr) in enumerate(zip(frame_func, frame_addr)):
            res_idx = func_res[fni]
            res_name = res_names[res_idx] if res_idx is not None else None
            if res_name == "cleave.bench" and addr >= 0:
                i = bisect.bisect_right(sym_addrs, addr) - 1
                if i >= 0:
                    frame_sym[fi] = simplify(syms[i][1])
            else:
                name_idx = func_name_idx[fni]
                if name_idx is not None:
                    fname = string_array[name_idx]
                    frame_sym[fi] = f"[{res_name}] {fname}" if res_name else fname

        target_frames = {fi for fi, (fni, addr) in enumerate(zip(frame_func, frame_addr)) if addr == target_addr}
        if not target_frames:
            continue

        for stack_idx in thread["samples"]["stack"]:
            if stack_idx is None:
                continue
            # Look for target in stack
            cur = stack_idx
            hit = False
            while cur is not None:
                fi = stack_frame[cur]
                if fi in target_frames:
                    hit = True
                    # Walk up to find first non-target caller
                    p = stack_prefix[cur]
                    first_caller = None
                    second_caller = None
                    while p is not None:
                        cfi = stack_frame[p]
                        if cfi not in target_frames:
                            name = frame_sym.get(cfi, f"addr=0x{frame_addr[frame_func[cfi]]:x}")
                            if first_caller is None:
                                first_caller = name
                            else:
                                second_caller = name
                                break
                        p = stack_prefix[p]
                    if first_caller:
                        caller_counts[first_caller] += 1
                    if second_caller:
                        caller_2[second_caller] += 1
                    total += 1
                    break
                cur = stack_prefix[cur]

    print(f"Total stacks with {hex(target_addr)}: {total}\n")
    print(f"Immediate callers:")
    print(f"{'Samples':>8}  {'%':>6}  Caller")
    print("-" * 100)
    for name, c in caller_counts.most_common(15):
        print(f"{c:>8}  {100*c/total:>5.2f}%  {name}")
    print()
    print(f"Second-level callers:")
    for name, c in caller_2.most_common(15):
        print(f"{c:>8}  {100*c/total:>5.2f}%  {name}")

if __name__ == "__main__":
    main()
