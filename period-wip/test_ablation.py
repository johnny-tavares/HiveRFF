import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import run_ablation as a


class Ablation(unittest.TestCase):
    def test_matched_seeds_and_rotating_order(self):
        with contextlib.redirect_stdout(io.StringIO()) as output:
            self.assertEqual(a.main(['--dry-run', '--trials', '4']), 0)
        lines=[line for line in output.getvalue().splitlines() if line.startswith('Replicate')]
        self.assertEqual(len(lines),16)
        for trial in range(4):
            group=lines[4*trial:4*trial+4]
            self.assertTrue(all(f'--seed-base {100+16*trial} ' in line for line in group))
            self.assertTrue(all('--afl-sync on' in line for line in group))
            for frequency, novelty in a.MODES:
                self.assertEqual(sum(f'--frequency {frequency} --novelty {novelty}' in line for line in group),1)
        self.assertEqual(len({line.split('--frequency ')[1] for line in lines[::4]}),4)

    def test_saved_manifest_and_stop_on_incomplete_metrics(self):
        for complete in [True,False]:
            with tempfile.TemporaryDirectory() as temp:
                root=Path(temp); calls=[]
                def fake_run():
                    calls.append(a.runner.sharing_settings())
                    path=root/'experiments'/str(len(calls));path.mkdir(parents=True)
                    (path/'record.json').write_text(json.dumps({'measurement_complete':complete,
                        'worker_abort_reasons':[], 'manager_returncode_after_stop':0}))
                    return path, {'status':'completed','trials':[{'record':'record.json'}]}
                with patch.object(a.runner,'OUT_ROOT',root), patch.object(a.runner,'main',side_effect=fake_run), contextlib.redirect_stdout(io.StringIO()):
                    if complete: self.assertEqual(a.main(['--trials','1']),0)
                    else:
                        with self.assertRaisesRegex(RuntimeError,'Incomplete metrics'): a.main(['--trials','1'])
                manifest=json.loads(next(root.glob('ablations/*/ablation.json')).read_text())
                self.assertEqual(manifest['status'],'completed' if complete else 'failed')
                self.assertEqual(len(calls),4 if complete else 1)
                self.assertEqual(len(manifest['runs']),len(calls))


if __name__=='__main__': unittest.main()
