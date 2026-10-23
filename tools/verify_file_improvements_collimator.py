"""Check retained facts with the shipping collimator extractor and Azoth specs.

Run with ../collimator/.venv/bin/python; CASE_DIRECTORY contains native codec
benchmark outputs. This verifies model-input compatibility, not dataset-loader
support for the diagnostic joined wire version.
"""
import dataclasses
import hashlib
import json
import pathlib
import sys
import numpy as np

sys.path.insert(0, str(pathlib.Path('../collimator/src').resolve()))
from collimator import features


def compatibility(doc):
    # Exact model-facing part of compact v8's finding coalescing contract.
    out = dict(doc, v='8')
    files = []
    for source in doc['files']:
        f = dict(source)
        traits = {}
        for source_trait in f.get('traits', []):
            t = dict(source_trait)
            grade = 0 if t['crit'] == 6 else t['crit']
            if t['id'] in traits:
                traits[t['id']]['crit'] = max(traits[t['id']]['crit'], grade)
            else:
                t['crit'] = grade
                traits[t['id']] = t
        f['traits'] = list(traits.values())
        files.append(f)
    out['files'] = files
    return out


def main():
    cases = pathlib.Path(sys.argv[1])
    models = pathlib.Path(sys.argv[2] if len(sys.argv) > 2 else '../azoth')
    manifest = json.loads(pathlib.Path('src/model_facts_manifest.json').read_text())
    config = json.loads((models/'config.json').read_text())
    contexts = []
    for entry in config['models']:
        path = models/entry['route']/'feature_spec.json'
        assert hashlib.sha256(path.read_bytes()).hexdigest() == manifest['feature_specs'][entry['route']]
        contexts.append((entry['route'], features.FeatureSpec.load(path)))
    enabled = dataclasses.replace(features.feature_config_from_env(),
        include_extended_metrics=True, include_attack_features=True,
        include_attack_code_ngrams=True, include_crit_category_ngrams=True,
        include_tiered_crit_bigrams=True, include_code_entropy_spike=True,
        include_hostile_finding_density=True)
    features.feature_config_from_env = lambda: enabled
    reports = 0
    for folder in sorted(p for p in cases.iterdir() if p.is_dir() and (p/'v8.json').exists()):
        before = json.loads((folder/'v8.json').read_text())
        after = compatibility(json.loads((folder/'trimmed.json').read_text()))
        assert after['fp'] == manifest['id']
        for route, spec in contexts:
            a, b = features.extract(before, spec), features.extract(after, spec)
            assert np.array_equal(a, b, equal_nan=True), (folder.name, route,
                [spec.feature_names[i] for i in np.flatnonzero(a != b)])
        reports += 1
        print(folder.name, 'collimator vectors equal', flush=True)
    result = dict(reports=reports, routes=len(contexts), equal_vectors=reports*len(contexts),
                  profile=manifest['id'], extractor_sha256=hashlib.sha256(pathlib.Path('../collimator/src/collimator/features.py').read_bytes()).hexdigest(),
                  scope='shipping collimator extractor, all declared gated families enabled; model compatibility projection, not joined dataset ingestion')
    (cases/'collimator-parity.json').write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps(result))


if __name__ == '__main__':
    main()
