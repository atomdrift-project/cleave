#!/usr/bin/env python3
"""Look at raw addresses/resources of frames attributed to low-address leaf samples
so we can figure out what 0xc88 / 0x3c27 etc. actually are."""
import bisect, gzip, json, subprocess, sys
from collections import Counter

BINARY = "out/cleave.bench"

def load_symbols(binary):
    out = subprocess.check_output(["nm", "-n", "--demangle", binary], stderr=subprocess.DEVNULL, text=True)
    syms = [(int(p[0], 16) - 0x100000000, p[2]) for line in out.splitlines()
            if len(p := line.split(None, 2)) == 3 and p[1] in ("t", "T")]
    return syms

def main():
    profile_path = sys.argv[1]
    target = sys.argv[2]  # e.g. "0xc88"
    base = "/Users/t/dev/atomdrift/cleave"
    with gzip.open(profile_path) as f:
        profile = json.load(f)

    cleave_pid = next(t["pid"] for t in profile["threads"] if t["name"] != "rizin")
    # For each frame with matching address text, show the resource (lib) name
    addr_target = int(target, 16)

    resource_hits = Counter()
    total_hits = 0

    for thread in (t for t in profile["threads"] if t["pid"] == cleave_pid):
        rt = thread["resourceTable"]
        res_names = [thread["stringArray"][i] if i is not None else None for i in rt["name"]]
        func_res = thread["funcTable"]["resource"]
        frame_func, frame_addr = thread["frameTable"]["func"], thread["frameTable"]["address"]
        stack_frame, stack_prefix = thread["stackTable"]["frame"], thread["stackTable"]["prefix"]

        # Build frame -> (resource_name, addr)
        frame_info = {}
        for fi, (fni, addr) in enumerate(zip(frame_func, frame_addr)):
            if addr == addr_target:
                res_idx = func_res[fni]
                res_name = res_names[res_idx] if res_idx is not None else None
                frame_info[fi] = (res_name, addr)

        for stack_idx in thread["samples"]["stack"]:
            if stack_idx is None:
                continue
            cur = stack_idx
            while cur is not None:
                fi = stack_frame[cur]
                if fi in frame_info:
                    res_name, addr = frame_info[fi]
                    resource_hits[res_name] += 1
                    total_hits += 1
                    break
                cur = stack_prefix[cur]

    print(f"Samples where the leaf is address {target}: {total_hits}")
    print()
    print(f"{'Samples':>8}  Resource")
    print("-" * 80)
    for res, c in resource_hits.most_common(20):
        print(f"{c:>8}  {res}")

    # Also show what comes directly ABOVE a 0xc88 frame — who calls it?
    caller_counts = Counter()
    for thread in (t for t in profile["threads"] if t["pid"] == cleave_pid):
        rt = thread["resourceTable"]
        res_names = [thread["stringArray"][i] if i is not None else None for i in rt["name"]]
        func_res = thread["funcTable"]["resource"]
        frame_func, frame_addr = thread["frameTable"]["func"], thread["frameTable"]["address"]
        stack_frame, stack_prefix = thread["stackTable"]["frame"], thread["stackTable"]["prefix"]
        string_array = thread["stringArray"]
        func_name_idx = thread["funcTable"]["name"]

        # Load cleave symbols for cleave.bench resource
        syms = load_symbols(f"{base}/{BINARY}")
        sym_addrs = [s[0] for s in syms]
        def simplify(n):
            if "::" in n:
                parts = n.rsplit("::", 1)
                if len(parts[1]) == 17 and parts[1][0] == "h":
                    n = parts[0]
            return n

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
                    frame_sym[fi] = f"[{res_name}] {string_array[name_idx]}"

        for stack_idx in thread["samples"]["stack"]:
            if stack_idx is None:
                continue
            cur = stack_idx
            while cur is not None:
                fi = stack_frame[cur]
                if frame_addr[frame_func[fi]] == addr_target:
                    # Walk up to find caller
                    p = stack_prefix[cur]
                    while p is not None:
                        cfi = stack_frame[p]
                        if frame_addr[frame_func[cfi]] != addr_target:
                            name = frame_sym.get(cfi, f"addr={frame_addr[frame_func[cfi]]:#x}")
                            caller_counts[name] += 1
                            break
                        p = stack_prefix[p]
                    break
                cur = stack_prefix[cur]
        break  # Only process first matching thread (already walked all)

    print()
    print(f"Callers of {target} (first walk):")
    print(f"{'Samples':>8}  Caller")
    print("-" * 100)
    for name, c in caller_counts.most_common(15):
        print(f"{c:>8}  {name}")

if __name__ == "__main__":
    main()
