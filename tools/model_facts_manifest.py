"""Generate the model-facts contract from the shipping Azoth route specs.

No experiment presets or ONNX runtime required. The earlier tree audit verified
that the declared metric union equals the tree-used union for this bundle.

usage: model_facts_manifest.py MODEL-BUNDLE TRAINING-CHECKOUT [proven-metrics.json]
                              [--training-specs DIRECTORY ...]

Training spec directories are searched recursively for feature_spec.json. Include
candidate layouts to audit feature dependencies; the shipping bundle alone
may have pruned their inputs. Metric maps are retained in full because
training discovers its vocabulary from the corpus, before a layout exists. Symbol vocabularies retain all existing capped
symbol rows, so new vocabulary tokens do not require a producer rebuild.

A metric stays in the contract once a model has used it: the prior contract's
metrics carry over, and proven-metrics.json (a list of flat metric names) adds
more.
"""
import argparse
import ast
import hashlib
import json
import pathlib

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('bundle', type=pathlib.Path)
parser.add_argument('collimator', type=pathlib.Path)
parser.add_argument('proven_metrics', nargs='?', type=pathlib.Path)
parser.add_argument('--training-specs', action='append', type=pathlib.Path, default=[])
args = parser.parse_args()
root, collimator = args.bundle, args.collimator
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
training_specs = {}
for directory in args.training_specs:
    paths = sorted(directory.rglob('feature_spec.json'))
    if not paths:
        raise ValueError(f'No feature specs found in {directory}')
    for spec_path in paths:
        spec = json.loads(spec_path.read_bytes())
        names = spec['feature_names']
        names_union.update(names)
        metrics.update(n.removeprefix('metrics:') for n in names if n.startswith('metrics:'))
        families.update(n.split(':')[0] for n in names)
        training_specs[str(spec_path.relative_to(directory))] = hashlib.sha256(spec_path.read_bytes()).hexdigest()
# Families computed only from file types, findings, formula, score, archive
# links or the training row's cluster: no fact can starve them.
fact_free = {'cluster','filetype','format','ghost','inter','missing'}
allowed = {'agg','atkbi','atktri','bigrams','crit','critbi','crittri','elements',
           'ext','formula','gap','intent_gap','maxcrit','mbcbi','mbctri',
           'metrics','present','rare','score','skeleton','struct','tierbi',
           'trigram','unsigned_bigram','symbol','symbol_bi','symbol_tri','kv','tiertri','tierquad'} | fact_free
assert families <= allowed, families-allowed
assert not any(m.startswith('derived_') for m in metrics), 'Audit derived inputs'
metrics.update(('binary_overall_entropy','text_total_lines'))
metrics.update(prior['metrics'])
if args.proven_metrics:
    metrics.update(json.loads(args.proven_metrics.read_text()))

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
# Vocabulary parameters need no new facts. New scalar feature semantics require
# a fresh dependency audit, even when they reuse an existing family prefix.
parameterized = {'present','maxcrit','bigrams','trigram','unsigned_bigram',
                 'crit','critbi','crittri','atkbi','atktri','mbcbi','mbctri',
                 'tierbi','elements','rare','skeleton','symbol','symbol_bi','symbol_tri','kv','tiertri','tierquad'} | fact_free
# Scalars outside the shipping specs that read only findings, file types,
# paths, archive links or mtimes (audited 2026-10-24), so training layouts pass
# `supports`.
# These aggregates read retained finding criticalities, not reduced facts.
finding_features = {
    'agg:crit3_finding_fraction', 'agg:crit4_finding_fraction',
    'agg:hostile_finding_fraction', 'agg:severe_to_mundane_ratio', 'agg:crit4_present',
    'agg:docobf_obfuscation_count', 'agg:docobf_eval_count', 'agg:docobf_lure_count',
    'agg:docobf_total_count', 'agg:docobf_has_any'}
audited = set(prior['fixed_features']) | finding_features | {
    'agg:hostile_depth_weight', 'ext:has_yara_match', 'intent_gap:network',
    'struct:air_gap_signal', 'struct:anachronistic_injection',
    'struct:extension_mismatch_signal', 'struct:foreign_binary_signal',
    'struct:inner_file_ratio', 'struct:max_nesting_depth_log',
    'struct:mtime_range_hours', 'struct:mtime_std_dev_hours', 'struct:zero_findings'}
audited = sorted(n for n in audited if n.split(':')[0] not in parameterized)
new_scalar = {n for n in names_union if n.split(':')[0] not in parameterized | {'metrics'}} - set(audited)
assert not new_scalar, ('Audit new scalar inputs before extending this contract', sorted(new_scalar))
contract = dict(metrics=sorted(metrics), gap_tokens=sorted(gaps), families=sorted(allowed),
                symbols='all', all_metrics=True, parameterized_families=sorted(parameterized), fixed_features=audited)
identifier = 'azoth-'+hashlib.sha256(json.dumps(contract,sort_keys=True,separators=(',',':')).encode()).hexdigest()[:16]
# Keep historical coverage separate: adding retained inputs cannot restore
# symbols/metrics omitted from reports already stored under an older ID.
previous = dict(prior.get('previous_profiles', {}))
if prior['id'] != identifier:
    previous[prior['id']] = {k: v for k, v in prior.items()
                            if k in contract or k == 'id'}
for profile in previous.values():
    profile['fixed_features'] = sorted(set(profile['fixed_features']) | finding_features)
    # Tiered combinations also read only retained findings.
    for key in ('families', 'parameterized_families'):
        profile[key] = sorted(set(profile[key]) | {'tiertri', 'tierquad'})
manifest = dict(id=identifier, model_set_hash=config['model_set_hash'],
                feature_specs=specs, training_specs=training_specs,
                previous_profiles=previous, **contract)
path.write_text(json.dumps(manifest,indent=2)+'\n')
print(identifier, len(metrics), 'metrics;', len(specs), 'routes')
