"""Generate the model-facts contract from the shipping Azoth route specs.

No experiment presets or ONNX runtime required. The earlier tree audit verified
that the declared metric union equals the tree-used union for this bundle.
"""
import hashlib
import json
import pathlib
import sys

root = pathlib.Path(sys.argv[1] if len(sys.argv) > 1 else '../azoth')
config = json.loads((root/'config.json').read_bytes())
metrics, specs, families, names_union = set(), {}, set(), set()
for entry in config['models']:
    path = root/entry['route']/'feature_spec.json'
    spec = json.loads(path.read_bytes())
    names = spec['feature_names']
    names_union.update(names)
    metrics.update(n.removeprefix('metrics:') for n in names if n.startswith('metrics:'))
    families.update(n.split(':')[0] for n in names)
    specs[entry['route']] = hashlib.sha256(path.read_bytes()).hexdigest()
allowed = {'agg','atkbi','atktri','bigrams','crit','critbi','crittri','elements',
           'ext','formula','gap','intent_gap','inter','maxcrit','mbcbi','mbctri',
           'metrics','missing','present','rare','score','skeleton','struct','tierbi',
           'trigram','unsigned_bigram'}
assert families <= allowed, families-allowed
assert not any(m.startswith('derived_') for m in metrics), 'Audit derived inputs'
metrics.update(('binary_overall_entropy','text_total_lines'))
gaps = ['BCryptOpenAlgorithmProvider','CreateProcess','CryptAcquireContext',
        'Crypto','ShellExecute','cryptography','curl','hashlib','http','os.spawn',
        'os.system','posix_spawn','requests','socket','subprocess','urllib','winhttp','wininet']
contract = {'metrics': sorted(metrics), 'gap_tokens': sorted(gaps), 'families':sorted(allowed)}
identifier = 'azoth-'+hashlib.sha256(json.dumps(contract,sort_keys=True,separators=(',',':')).encode()).hexdigest()[:16]
# Vocabulary parameters need no new facts. New scalar feature semantics require
# a fresh dependency audit, even when they reuse an existing family prefix.
parameterized = {'present','maxcrit','bigrams','trigram','unsigned_bigram',
                 'crit','critbi','crittri','atkbi','atktri','mbcbi','mbctri',
                 'tierbi','elements','rare','skeleton'}
prior_path = pathlib.Path('src/model_facts_manifest.json')
prior = json.loads(prior_path.read_text()) if prior_path.exists() else {}
audited = prior.get('fixed_features')
if audited is None:
    audited = [n for n in json.loads(pathlib.Path('docs/json3-model-facts-audit.json').read_text())['declared_features']
               if n.split(':')[0] not in parameterized | {'metrics'}]
new_scalar = {n for n in names_union if n.split(':')[0] not in parameterized | {'metrics'}} - set(audited)
assert not new_scalar, ('Audit new scalar inputs before extending this contract', sorted(new_scalar))
manifest = dict(id=identifier, model_set_hash=config['model_set_hash'],
                feature_specs=specs, parameterized_families=sorted(parameterized),
                fixed_features=sorted(audited), **contract)
path = pathlib.Path('src/model_facts_manifest.json')
path.write_text(json.dumps(manifest,indent=2)+'\n')
print(identifier, len(metrics), 'metrics;', len(specs), 'routes')
