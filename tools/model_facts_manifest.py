"""Generate the model-facts contract from the shipping Azoth route specs.

No experiment presets or ONNX runtime required. The earlier tree audit verified
that the declared metric union equals the tree-used union for this bundle.

usage: model_facts_manifest.py [azoth-bundle] [collimator-checkout] [proven-metrics.json]

A metric stays in the contract once a model has used it: the prior contract's
metrics carry over, and proven-metrics.json (a list of flat metric names) adds
more. It was seeded 2026-10-24 with every metric an azoth model ever split on.
"""
import ast
import hashlib
import json
import pathlib
import sys

root = pathlib.Path(sys.argv[1] if len(sys.argv) > 1 else '../azoth')
collimator = pathlib.Path(sys.argv[2] if len(sys.argv) > 2 else '../collimator')
path = pathlib.Path('src/model_facts_manifest.json')
prior = json.loads(path.read_text())
config = json.loads((root/'config.json').read_bytes())
metrics, specs, families, names_union = set(), {}, set(), set()
for entry in config['models']:
    spec_path = root/entry['route']/'feature_spec.json'
    spec = json.loads(spec_path.read_bytes())
    names = spec['feature_names']
    names_union.update(names)
    metrics.update(n.removeprefix('metrics:') for n in names if n.startswith('metrics:'))
    families.update(n.split(':')[0] for n in names)
    specs[entry['route']] = hashlib.sha256(spec_path.read_bytes()).hexdigest()
# Families computed only from file types, findings, formula, score, archive
# links or the training row's cluster: no fact can starve them.
fact_free = {'cluster','filetype','format','ghost','inter','missing'}
allowed = {'agg','atkbi','atktri','bigrams','crit','critbi','crittri','elements',
           'ext','formula','gap','intent_gap','maxcrit','mbcbi','mbctri',
           'metrics','present','rare','score','skeleton','struct','tierbi',
           'trigram','unsigned_bigram'} | fact_free
assert families <= allowed, families-allowed
assert not any(m.startswith('derived_') for m in metrics), 'Audit derived inputs'
metrics.update(('binary_overall_entropy','text_total_lines'))
metrics.update(prior['metrics'])
if len(sys.argv) > 3:
    metrics.update(json.loads(pathlib.Path(sys.argv[3]).read_text()))

def collimator_literal(name):
    """A module-level literal from collimator's features.py, frozenset or not."""
    module = ast.parse((collimator/'src/collimator/features.py').read_text())
    node = next(n.value for n in ast.walk(module) if isinstance(n, ast.AnnAssign)
                and getattr(n.target, 'id', None) == name)
    if isinstance(node, ast.Call):  # frozenset({...})
        node = node.args[0]
    return ast.literal_eval(node)

# Kept regardless of frequency because the signal is rare but decisive.
metrics.update(collimator_literal('ALWAYS_KEEP_METRICS'))
# Models keep a metric's old name and collimator back-fills it from the
# renamed report key (_METRIC_RENAMES), so retain the report key.
metrics.update(new.replace('.', '_', 1) for old, new in collimator_literal('_METRIC_RENAMES').items()
               if old.replace('.', '_', 1) in metrics)
gaps = ['BCryptOpenAlgorithmProvider','CreateProcess','CryptAcquireContext',
        'Crypto','ShellExecute','cryptography','curl','hashlib','http','os.spawn',
        'os.system','posix_spawn','requests','socket','subprocess','urllib','winhttp','wininet']
contract = {'metrics': sorted(metrics), 'gap_tokens': sorted(gaps), 'families':sorted(allowed)}
identifier = 'azoth-'+hashlib.sha256(json.dumps(contract,sort_keys=True,separators=(',',':')).encode()).hexdigest()[:16]
# Vocabulary parameters need no new facts. New scalar feature semantics require
# a fresh dependency audit, even when they reuse an existing family prefix.
parameterized = {'present','maxcrit','bigrams','trigram','unsigned_bigram',
                 'crit','critbi','crittri','atkbi','atktri','mbcbi','mbctri',
                 'tierbi','elements','rare','skeleton'} | fact_free
# Scalars outside the shipping specs that read only findings, file types,
# paths, archive links or mtimes (audited 2026-10-24), so training layouts pass
# `supports`.
audited = set(prior['fixed_features']) | {
    'agg:hostile_depth_weight', 'ext:has_yara_match', 'intent_gap:network',
    'struct:air_gap_signal', 'struct:anachronistic_injection',
    'struct:extension_mismatch_signal', 'struct:foreign_binary_signal',
    'struct:inner_file_ratio', 'struct:max_nesting_depth_log',
    'struct:mtime_range_hours', 'struct:mtime_std_dev_hours', 'struct:zero_findings'}
audited = sorted(n for n in audited if n.split(':')[0] not in parameterized)
new_scalar = {n for n in names_union if n.split(':')[0] not in parameterized | {'metrics'}} - set(audited)
assert not new_scalar, ('Audit new scalar inputs before extending this contract', sorted(new_scalar))
manifest = dict(id=identifier, model_set_hash=config['model_set_hash'],
                feature_specs=specs, parameterized_families=sorted(parameterized),
                fixed_features=audited, **contract)
path.write_text(json.dumps(manifest,indent=2)+'\n')
print(identifier, len(metrics), 'metrics;', len(specs), 'routes')
