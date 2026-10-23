"""Build an illustrative, self-contained schema-9 single-file comparison.

Usage (with collimator's Python environment):
  python tools/model_json3_file.py CURRENT_JSON OUTPUT_DIRECTORY

Design prototype only. Keeps inline historical definitions, current metric
objects, and every non-facts field. No shared catalog or column elision.
"""
import copy
import hashlib
import json
import pathlib
import sys

import audit_json3_model_facts as audit
import measure_json3_design as codec


FIELD_MAP = {
    "sha": "h", "size": "z", "type": "y", "ident": "i",
    "facts": "f", "supp": "u", "analysis_gaps": "g",
}
PLACEMENT = {"id", "path", "depth", "pid", "dp", "rel", "via", "role"}


def encode(report):
    assert len(report["files"]) == 1
    file = copy.deepcopy(report["files"][0])
    placement = {key: file.pop(key) for key in list(file) if key in PLACEMENT}
    findings = file.pop("traits", None)
    if findings is not None:
        file["t"] = []
        for finding in findings:
            definition = [finding.get(key) for key in ("id", "desc", "mbc", "atk")]
            assert "id" in finding and "desc" in finding
            assert all(finding[key] is not None for key in finding)
            codec.trim(definition)
            detail = {({"spans": "e", "uses": "u"}.get(key, key)): value
                      for key, value in finding.items()
                      if key not in ("id", "desc", "mbc", "atk", "crit", "conf")}
            row = [definition, finding["crit"], finding["conf"]]
            if detail:
                row.append(detail)
            file["t"].append(row)
    codec.context_encode({"files": [file]})
    for row in file.get("c", []):
        if row[1] == 0 and "\0" in row[2]:
            row[1], row[2] = 1, codec.zencode(row[2].encode())
    analysis = {FIELD_MAP.get(key, key): value for key, value in file.items()}
    assert "q" not in analysis
    analysis["q"] = 2 if file.get("analysis_gaps") else 1
    out = {key: value for key, value in report.items() if key not in ("v", "files")}
    return dict(v=9, profile="azoth-facts-1", **out, a=[analysis], n=[[0, placement]], r=[0])


def decode(report):
    reverse = {value: key for key, value in FIELD_MAP.items()}
    file = {reverse.get(key, key): value for key, value in copy.deepcopy(report["a"][0]).items() if key != "q"}
    if "t" in file:
        findings = []
        for row in file.pop("t"):
            definition = {key: value for key, value in zip(("id", "desc", "mbc", "atk"), row[0]) if value is not None}
            details = {({"e": "spans", "u": "uses"}.get(key, key)): value for key, value in (row[3] if len(row) > 3 else {}).items()}
            findings.append(dict(definition, crit=row[1], conf=row[2], **details))
        file["traits"] = findings
    codec.context_decode({"files": [file]})
    file.update(report["n"][0][1])
    return dict(v="8", **{key: value for key, value in report.items()
                          if key not in ("v", "profile", "a", "n", "r")}, files=[file])


def main():
    path, output = map(pathlib.Path, sys.argv[1:])
    sys.path.insert(0, str(pathlib.Path("../collimator/src")))
    from collimator import features

    current = json.loads(path.read_bytes())
    assert current["v"] == "8" and len(current["files"]) == 1
    manifest = json.loads(pathlib.Path("docs/json3-model-facts-audit.json").read_bytes())
    metric_names, gap_names = set(manifest["metric_inputs"]), set(manifest["gap_tokens"])
    projected = copy.deepcopy(current)
    projected["files"][0]["facts"] = audit.project_facts(
        current["files"][0]["facts"], metric_names, gap_names, features)
    proposed = encode(projected)
    assert decode(json.loads(codec.wire(proposed))) == projected
    checks = audit.verify_projection([path], pathlib.Path("../azoth"), manifest["routes"],
                                     metric_names, gap_names, features)
    output.mkdir(parents=True, exist_ok=True)
    sizes = {}
    for name, data in (("current", current), ("retained-facts", projected), ("proposed", proposed)):
        payload = codec.wire(data)
        (output / f"{name}.min.json").write_bytes(payload)
        (output / f"{name}.json").write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n")
        sizes[name] = len(payload)
    f = current["files"][0]
    summary = {
        "source": f["path"], "artifact_sha256": f["sha"], "artifact_size": f["size"],
        "artifact_type": f["type"], "traits_revision": current.get("rev"),
        "current_report_sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
        "model_set_hash": manifest["model_set_hash"], "compact_json_bytes": sizes,
        "current_section_bytes": {key: len(codec.wire(value)) for key, value in f.items()},
        "retained_facts": projected["files"][0]["facts"],
        "findings": len(f.get("traits", [])), "context_windows": len(f.get("ctx", [])),
        "context_encodings": {"utf8": sum(row[1] == 0 for row in proposed["a"][0].get("c", [])),
                              "z85": sum(row[1] == 1 for row in proposed["a"][0].get("c", []))},
        "projection_verification": checks, "roundtrip_to_projected_v8": True,
        "scope": "illustrative self-contained v9; raw JSON sizes, no TOAST measurement; only facts intentionally omitted",
    }
    (output / "measurements.json").write_text(json.dumps(summary, indent=2) + "\n")
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
