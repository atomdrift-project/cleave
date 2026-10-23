"""Reversible context-layout experiment; deliberately not a production reader.

Usage: python3 tools/pack_context_experiment.py FILE_1_JSON OUTPUT_DIRECTORY
       --renderer ../scan/target/debug/atomscan

Measures packed objects, packed tuples, and a tuple-only control. Every variant
must restore the entire input JSON value and the actual scan interpret output.
"""
import argparse
import copy
import json
import pathlib
import subprocess

from measure_json3_design import zdecode, zencode


VARIANTS = ("packed-objects", "packed-tuples", "window-tuples")


def wire(value):
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode()


def pack(document, variant):
    if document.get("v") != "file-1" or variant not in VARIANTS:
        raise ValueError("expected file-1 and a supported experiment")
    result = copy.deepcopy(document)
    result["v"] = "experiment-" + variant
    for file in result["files"]:
        if "ctx" not in file:
            continue
        windows, content = [], bytearray()
        for window in file["ctx"]:
            extra = {k: v for k, v in window.items() if k not in ("ln", "b")}
            data = zdecode(window["b"])
            if variant == "packed-objects":
                windows.append(dict(ln=window["ln"], len=len(data), **extra))
            else:
                payload = window["b"] if variant == "window-tuples" else len(data)
                windows.append([window["ln"], payload, extra] if extra else [window["ln"], payload])
            content.extend(data)
        file["ctx"] = windows if variant == "window-tuples" else dict(b=zencode(content), ranges=windows)
    return result


def unpack(document):
    result = copy.deepcopy(document)
    variant = result.get("v", "").removeprefix("experiment-")
    if result.get("v") != "experiment-" + variant or variant not in VARIANTS:
        raise ValueError("unsupported experiment version")
    result["v"] = "file-1"
    for file in result["files"]:
        if "ctx" not in file:
            continue
        packed = variant != "window-tuples"
        context = file["ctx"]
        content = zdecode(context["b"]) if packed else b""
        windows = context["ranges"] if packed else context
        restored, position = [], 0
        for window in windows:
            if variant == "packed-objects":
                offset, payload = window["ln"], window["len"]
                extra = {k: v for k, v in window.items() if k not in ("ln", "len")}
            else:
                if len(window) not in (2, 3):
                    raise ValueError("expected [offset, payload, optional metadata]")
                offset, payload = window[:2]
                extra = window[2] if len(window) == 3 else {}
            if "ln" in extra or "b" in extra:
                raise ValueError("metadata must not override offset or content")
            if packed:
                if type(payload) is not int or payload < 0 or payload > len(content) - position:
                    raise ValueError("invalid packed window length")
                data = zencode(content[position:position + payload])
                position += payload
            else:
                data = payload
            restored.append(dict(ln=offset, b=data, **extra))
        if packed and position != len(content):
            raise ValueError("unreferenced bytes in packed context")
        file["ctx"] = restored
    return result


def render(renderer, path):
    return subprocess.run(
        [renderer, "render", str(path), "--format", "interpret"],
        check=True, capture_output=True,
    ).stdout


def overlap_bytes(document):
    duplicated = 0
    for file in document["files"]:
        end = 0
        for lo, length in sorted((w["ln"], len(zdecode(w["b"]))) for w in file.get("ctx", [])):
            duplicated += max(0, min(end, lo + length) - lo)
            end = max(end, lo + length)
    return duplicated


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", type=pathlib.Path)
    parser.add_argument("output", type=pathlib.Path)
    parser.add_argument("--renderer", required=True)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=True)
    original = json.loads(args.input.read_bytes())
    baseline = wire(original)
    baseline_path = args.output / "baseline.min.json"
    baseline_path.write_bytes(baseline)
    (args.output / "baseline.json").write_text(json.dumps(original, indent=2, ensure_ascii=False) + "\n")
    expected = render(args.renderer, baseline_path)
    (args.output / "baseline.interpret.txt").write_bytes(expected)
    measurements = {"input": str(args.input), "baseline_bytes": len(baseline),
                    "baseline_context_bytes": sum(len(wire(f["ctx"])) for f in original["files"] if "ctx" in f),
                    "overlapping_content_bytes": overlap_bytes(original), "variants": {}}
    for variant in VARIANTS:
        candidate = pack(original, variant)
        encoded = wire(candidate)
        (args.output / (variant + ".min.json")).write_bytes(encoded)
        (args.output / (variant + ".json")).write_text(json.dumps(candidate, indent=2, ensure_ascii=False) + "\n")
        restored = unpack(json.loads(encoded))
        if restored != original:
            raise AssertionError("complete document roundtrip failed: " + variant)
        restored_path = args.output / (variant + ".restored.json")
        restored_path.write_bytes(wire(restored))
        actual = render(args.renderer, restored_path)
        if actual != expected:
            raise AssertionError("interpret changed: " + variant)
        (args.output / (variant + ".interpret.txt")).write_bytes(actual)
        # Use the original version label to isolate layout cost. Actual exported
        # experiment bytes are also reported; longer labels are not free.
        candidate["v"] = original["v"]
        comparable = len(wire(candidate))
        measurements["variants"][variant] = {
            "export_bytes": len(encoded), "layout_bytes": comparable,
            "saved_bytes": len(baseline) - comparable,
            "saved_percent": round(100 * (len(baseline) - comparable) / len(baseline), 3),
            "context_bytes": sum(len(wire(f["ctx"])) for f in candidate["files"] if "ctx" in f),
            "complete_document_equal": True, "interpret_equal": True,
        }
    measurements["scope"] = "Python prototype; scan renders the losslessly unpacked file-1 document; no native packed reader or runtime performance claim"
    (args.output / "measurements.json").write_text(json.dumps(measurements, indent=2) + "\n")
    print(json.dumps(measurements, indent=2))


if __name__ == "__main__":
    main()
