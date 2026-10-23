"""Design audit of shipping azoth ONNX inputs; never modifies reports/models.

Run with collimator's Python environment (onnx installed):
  ../collimator/.venv/bin/python tools/audit_json3_model_facts.py \
      --output docs/json3-model-facts-audit.json /path/to/v8-report.json ...

The projection is deliberately lossy outside current model inputs. Byte counts
are JSON text, not PostgreSQL storage. No inference-parity claim is made.
"""
import argparse
import collections
import dataclasses
import hashlib
import json
import pathlib
import sys

import onnx


def wire(value):
    return json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode()


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def audit_models(root):
    config = json.loads((root / "config.json").read_bytes())
    routes, used_union, declared_union = [], set(), set()
    for entry in config["models"]:
        directory = root / entry["route"]
        spec_path = directory / "feature_spec.json"
        spec = json.loads(spec_path.read_bytes())
        names = spec["feature_names"]
        used, models = set(), []
        paths = sorted((directory / "models").glob("seed_*.onnx"))
        assert paths, directory
        for path in paths:
            model = onnx.load(path, load_external_data=False)
            tree_count = 0
            for node in model.graph.node:
                if node.op_type not in ("TreeEnsembleClassifier", "TreeEnsembleRegressor"):
                    continue
                tree_count += 1
                attrs = {a.name: a for a in node.attribute}
                indices, modes = attrs["nodes_featureids"].ints, attrs["nodes_modes"].strings
                assert len(indices) == len(modes)
                for index, mode in zip(indices, modes):
                    if mode != b"LEAF":
                        used.add(names[index])
            assert tree_count, path
            models.append({"file": str(path.relative_to(root)), "sha256": digest(path)})
        used_union.update(used)
        declared_union.update(names)
        routes.append({
            "route": entry["route"], "spec_sha256": digest(spec_path), "models": models,
            "declared_count": len(names), "used_count": len(used),
            "metric_slots": sum(n.startswith("metrics:") for n in names),
            "used_metrics": sorted(n for n in used if n.startswith("metrics:")),
            "used_gaps": sorted(n for n in used if n.startswith("gap:")),
        })
    return {
        "model_set_hash": config["model_set_hash"], "timestamp": config["timestamp"],
        "config_sha256": digest(root / "config.json"), "routes": routes,
        "declared_features": sorted(declared_union), "used_features": sorted(used_union),
        "used_families": dict(sorted(collections.Counter(n.split(":")[0] for n in used_union).items())),
    }


def project_facts(facts, metric_names, gap_names, features):
    """Keep exact raw values/rows sufficient for current metric and gap inputs.

    Retains the union across every shipped route, not just a leaf specialist.
    Imports remain imports so Rust's import-only gap semantics are preserved;
    Python additionally considers exports/functions/targets/member chains.
    """
    out = {}
    metrics = {}
    for group, fields in facts.get("metrics", {}).items():
        if isinstance(fields, dict):
            kept = {key: value for key, value in fields.items()
                    if f"metrics:{group}_{key}" in metric_names}
            if kept:
                metrics[group] = kept
    if metrics:
        out["metrics"] = metrics
    for key in ("imp", "exp", "funcs", "tgt", "mbr"):
        kept = []
        for row in facts.get(key, []):
            tokens = features._file_symbols({"facts": {key: [row]}})
            if tokens & gap_names:
                kept.append(row)
        if kept:
            out[key] = kept
    assert (features._file_symbols({"facts": facts}) & gap_names
            == features._file_symbols({"facts": out}) & gap_names)
    return out


def audit_report(path, metric_names, gap_names, features):
    report = json.loads(path.read_bytes())
    report = report.get("raw", report)
    assert report.get("v") == "8"
    totals = {scope: collections.Counter() for scope in ("occurrences", "first_per_sha")}
    keys, kept_keys, seen = set(), set(), set()
    for file in report["files"]:
        for context in file.get("ctx", []):
            context.pop("n", None)
        facts = file.get("facts", {})
        projected = project_facts(facts, metric_names, gap_names, features)
        stats = {
            "records": 1, "facts_bytes": len(wire(facts)),
            "projected_facts_bytes": len(wire(projected)),
            "metrics_bytes": len(wire(facts.get("metrics", {}))),
            "projected_metrics_bytes": len(wire(projected.get("metrics", {}))),
            "file_bytes": len(wire(file)),
        }
        for group, fields in facts.get("metrics", {}).items():
            if isinstance(fields, dict):
                for key in fields:
                    keys.add((group, key))
                    stats["metric_entries"] = stats.get("metric_entries", 0) + 1
                    if f"metrics:{group}_{key}" in metric_names:
                        kept_keys.add((group, key))
                        stats["retained_metric_entries"] = stats.get("retained_metric_entries", 0) + 1
        totals["occurrences"].update(stats)
        sha = file.get("sha")
        if not sha or sha not in seen:
            totals["first_per_sha"].update(stats)
            seen.add(sha)
    return {"sample": path.name, "sha256": digest(path), "report_bytes": len(wire(report)),
            "distinct_metric_keys": len(keys), "retained_metric_keys": len(kept_keys),
            **totals}


def verify_projection(paths, root, routes, metric_names, gap_names, features):
    """Compare full vectors on bounded diverse fixtures, under shipped families.

    This is a local projection check, not cross-language/deployment parity.
    The declared feature layout determines output slots. Enable the gated
    families present in that layout, without importing experiment presets.
    """
    import numpy as np

    config = dataclasses.replace(
        features.feature_config_from_env(), include_extended_metrics=True,
        include_attack_features=True, include_attack_code_ngrams=True,
        include_crit_category_ngrams=True, include_tiered_crit_bigrams=True,
        include_code_entropy_spike=True, include_hostile_finding_density=True,
    )
    original_config = features.feature_config_from_env
    features.feature_config_from_env = lambda: config
    fixtures = []
    try:
        for path in paths:
            report = json.loads(path.read_bytes())
            report = report.get("raw", report)
            # Largest facts record per type, up to four types per report.
            by_type = {}
            for file in report["files"]:
                kind = file.get("type", "")
                length = len(wire(file.get("facts", {})))
                if kind not in by_type or length > by_type[kind][0]:
                    by_type[kind] = (length, file)
            selected = [f for _, f in sorted(by_type.values(), key=lambda pair: pair[0], reverse=True)[:4]]
            for file in selected:
                projected = dict(file, facts=project_facts(file.get("facts", {}), metric_names, gap_names, features))
                fixtures.append(({"files": [file]}, {"files": [projected]}))
            # Also exercise report-level aggregation over the selected members.
            fixtures.append(({"files": selected}, {"files": [dict(f, facts=project_facts(f.get("facts", {}), metric_names, gap_names, features)) for f in selected]}))
        for route in routes:
            spec = features.FeatureSpec.load(root / route["route"] / "feature_spec.json")
            for before, after in fixtures:
                a, b = features.extract(before, spec), features.extract(after, spec)
                assert np.array_equal(a, b, equal_nan=True), (route["route"], [spec.feature_names[i] for i in np.flatnonzero(a != b)])
        return {"fixtures": len(fixtures), "routes": len(routes),
                "equal_full_vectors": len(fixtures) * len(routes),
                "scope": "collimator extraction with shipped gated families enabled; no Rust parity or runtime score replay"}
    finally:
        features.feature_config_from_env = original_config


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--azoth", type=pathlib.Path, default=pathlib.Path("../azoth"))
    parser.add_argument("--collimator", type=pathlib.Path, default=pathlib.Path("../collimator"))
    parser.add_argument("--output", type=pathlib.Path, required=True)
    parser.add_argument("--verify", action="store_true", help="Compare full collimator feature vectors on bounded report fixtures")
    parser.add_argument("reports", type=pathlib.Path, nargs="*")
    args = parser.parse_args()
    sys.path.insert(0, str(args.collimator / "src"))
    from collimator import features

    result = audit_models(args.azoth)
    names = set(result["used_features"])
    assert not any(n.startswith(("symbol:", "symbol_bi:", "symbol_tri:", "kv:", "textenc:", "metrics:derived")) for n in names), "Re-audit new input dependencies"
    metric_names = {n for n in names if n.startswith("metrics:")}
    # Structural features also consume these; currently both are in the union.
    metric_names.update(("metrics:binary_overall_entropy", "metrics:text_total_lines"))
    gap_names = set().union(*(symbols for symbols, _ in features.LOGIC_GAPS.values()))
    result["metric_inputs"] = sorted(metric_names)
    result["gap_tokens"] = sorted(gap_names)
    result["extractor_sha256"] = digest(args.collimator / "src/collimator/features.py")
    result["measurement_scope"] = "raw JSON text; model-input projection, not full report preservation or TOAST benchmark"
    result["reports"] = []
    for path in args.reports:
        row = audit_report(path, metric_names, gap_names, features)
        result["reports"].append(row)
        print(json.dumps(row), flush=True)
    if args.verify:
        result["projection_verification"] = verify_projection(
            args.reports, args.azoth, result["routes"], metric_names, gap_names, features)
        print(json.dumps(result["projection_verification"]), flush=True)
    args.output.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps({"routes": len(result["routes"]),
                      "models": sum(len(r["models"]) for r in result["routes"]),
                      "metric_inputs": len(metric_names), "gap_tokens": len(gap_names),
                      "output": str(args.output)}), flush=True)


if __name__ == "__main__":
    main()
