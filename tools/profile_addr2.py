#!/usr/bin/env python3
"""Walk deeper up the stack to find cleave caller of an opaque address leaf."""
import bisect, gzip, json, subprocess, sys
from collections import Counter

BINARY = "out/cleave.bench"

def load_symbols(binary):
    out = subprocess.check_output(["nm", "-n", "--demangle", binary], stderr=subprocess.DEVNULL, text=True)
    return [(int(p[0], 16) - 0x100000000, p[2]) for line in out.splitlines()
            if len(p := line.split(None, 2)) == 3 and p[1] in ("t", "T")]

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

    cleave_caller = Counter()
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

        def sym_of(fi):
            fni = frame_func[fi]
            addr = frame_addr[fni]
            res_idx = func_res[fni]
            res_name = res_names[res_idx] if res_idx is not None else None
            if res_name == "cleave.bench" and addr >= 0:
                i = bisect.bisect_right(sym_addrs, addr) - 1
                if i >= 0:
                    return simplify(syms[i][1]), True
            name_idx = func_name_idx[fni]
            if name_idx is not None:
                return f"[{res_name}] {string_array[name_idx]}", False
            return None, False

        for stack_idx in thread["samples"]["stack"]:
            if stack_idx is None:
                continue
            cur = stack_idx
            found_target = False
            while cur is not None:
                fi = stack_frame[cur]
                if frame_addr[frame_func[fi]] == target_addr:
                    found_target = True
                    # walk up until we hit a cleave symbol
                    p = stack_prefix[cur]
                    while p is not None:
                        cfi = stack_frame[p]
                        name, is_cleave = sym_of(cfi)
                        if is_cleave:
                            cleave_caller[name] += 1
                            total += 1
                            break
                        p = stack_prefix[p]
                    break
                cur = stack_prefix[cur]

    print(f"Stacks with leaf {hex(target_addr)} and cleave caller resolved: {total}\n")
    print(f"{'Samples':>8}  {'%':>6}  Cleave caller")
    print("-" * 100)
    for name, c in cleave_caller.most_common(20):
        print(f"{c:>8}  {100*c/total:>5.2f}%  {name}")

if __name__ == "__main__":
    main()
