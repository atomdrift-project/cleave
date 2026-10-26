"""Contract generation checks; no scanner build or model runtime needed.

Run from the checkout: python -m unittest discover -s tools -p 'test_model_facts_manifest.py'
"""
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]


class ManifestTests(unittest.TestCase):
    def test_training_inputs_history_and_repeatable_identity(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for directory in ('src', 'bundle/general', 'collimator/src/collimator', 'training/native'):
                (root / directory).mkdir(parents=True)
            prior = json.loads((ROOT / 'src/model_facts_manifest.json').read_text())
            (root / 'src/model_facts_manifest.json').write_text(json.dumps(prior))
            (root / 'bundle/config.json').write_text(json.dumps({
                'models': [{'route': 'general'}], 'model_set_hash': 'fixture',
            }))
            (root / 'bundle/general/feature_spec.json').write_text(json.dumps({
                'feature_names': ['metrics:binary_overall_entropy'],
            }))
            training = root / 'training/native/feature_spec.json'
            training.write_text(json.dumps({'feature_names': [
                'symbol:fixture', 'symbol_bi:a||b', 'symbol_tri:a||b||c',
                'metrics:fixture_added', 'agg:crit4_present', 'kv:fixture.kind=native',
                'tiertri:a + b + c',
            ]}))
            (root / 'collimator/src/collimator/features.py').write_text(
                "ALWAYS_KEEP_METRICS: set = {'ast_depth_capped'}\n"
                "_METRIC_RENAMES: dict = {'fixture.added': 'fixture.renamed'}\n"
            )
            command = [sys.executable, str(ROOT / 'tools/model_facts_manifest.py'),
                       str(root / 'bundle'), str(root / 'collimator'),
                       '--training-specs', str(root / 'training')]
            subprocess.run(command, cwd=root, check=True, capture_output=True)
            path = root / 'src/model_facts_manifest.json'
            result = json.loads(path.read_text())
            self.assertNotEqual(prior['id'], result['id'])
            self.assertIn('fixture_added', result['metrics'])
            self.assertIn('fixture_renamed', result['metrics'])
            self.assertTrue(set(prior['metrics']) <= set(result['metrics']))
            self.assertEqual(result['symbols'], 'all')
            self.assertTrue(result['all_metrics'])
            self.assertNotIn('fixture_added', result['previous_profiles'][prior['id']]['metrics'])
            self.assertEqual(len(result['training_specs']), 1)
            first = path.read_bytes()
            subprocess.run(command, cwd=root, check=True, capture_output=True)
            self.assertEqual(path.read_bytes(), first)
            training.write_text(json.dumps({'feature_names': ['struct:unaudited_input']}))
            failure = subprocess.run(command, cwd=root, capture_output=True, text=True)
            self.assertNotEqual(failure.returncode, 0)
            self.assertIn('Audit new scalar inputs', failure.stderr)
            self.assertEqual(path.read_bytes(), first)


if __name__ == '__main__':
    unittest.main()
