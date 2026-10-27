import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

spec=importlib.util.spec_from_file_location('profile_report',Path(__file__).with_name('analyze_profile.py'))
p=importlib.util.module_from_spec(spec);spec.loader.exec_module(p)

class ProfileReport(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.root=Path(self.tmp.name)
        self.trial=self.root/'experiments'/'example'/'trial-001';self.trial.mkdir(parents=True)
        workers={}
        for i in range(2):
            name='worker_'+str(i);out=self.trial/'afl'/name;out.mkdir(parents=True)
            rows=[dict(schema_version=1,kind='selection',input_hash='input',parent_hash='parent',parent_present=True)]
            # Same spec appears across workers, but another input must stay distinct.
            for inp,schedule,shape,trace in [('input','shared','shape',10),('input','private'+str(i),'shape',11+i),('other'+str(i),'shared','shape',10)]:
                rows.append(dict(schema_version=1,kind='execution',input_hash=inp,schedule_hash=schedule,shape_hash=shape,outcome_trace=trace,interrupted=False))
            rows.append(dict(schema_version=1,kind='execution',input_hash='input',interrupted=True))
            (out/'profile.jsonl').write_text(''.join(json.dumps(r)+'\n' for r in rows))
            workers[name]={'metrics':dict(profiling_enabled=True,final=True,profile_rows=5,profile_dropped_rows=0,profile_selection_calls=1,profile_target_wall_calls=4,profile_target_wall_ns=2000000000)}
        self.record=dict(workers=workers,measurement_complete=True,sharing={'frequency':'global','novelty':'shared'},frequency_policy='guarded_frequency_energy_v4',totals={'schedule_executions_completed':6})
        self.path=self.trial/'record.json';self.save()
    def save(self): self.path.write_text(json.dumps(self.record))
    def tearDown(self): self.tmp.cleanup()
    def test_overlap_input_and_interrupted_semantics(self):
        report=p.analyze_trial(self.path)
        self.assertEqual(report['warnings'],[])
        self.assertEqual(report['overlap']['schedule']['union'],5)
        self.assertEqual(report['overlap']['schedule']['sum_worker_unique'],6)
        self.assertEqual(report['overlap']['shape']['union'],3)
        self.assertEqual(report['overlap']['trace']['union'],5)
        self.assertEqual(report['overlap']['parent']['union'],1)
        self.assertEqual(report['phase_worker_seconds']['target_wall'],4)
        self.assertEqual(report['workers']['worker_0']['logged_completed_executions'],3)
    def test_missing_disabled_truncated_and_malformed(self):
        self.record['workers']['worker_0']['metrics']['profile_dropped_rows']=4
        self.record['workers']['worker_0']['metrics']['final']=False
        self.record['workers']['worker_1']['metrics']['profiling_enabled']=False
        self.save()
        with (self.trial/'afl/worker_0/profile.jsonl').open('a') as f:f.write('{broken')
        warnings=' '.join(p.analyze_trial(self.path)['warnings'])
        for phrase in ['prefix','malformed','not final','disabled','all measured calls']:
            self.assertIn(phrase,warnings)
    def test_missing_file(self):
        (self.trial/'afl/worker_1/profile.jsonl').unlink()
        report=p.analyze_trial(self.path)
        self.assertIn('missing profile.jsonl',' '.join(report['warnings']))
        self.assertEqual(report['phase_worker_seconds']['target_wall'],4)
    def test_permission_error_preserves_timing(self):
        from unittest.mock import patch
        original=Path.open
        def guarded_open(path,*args,**kwargs):
            if path.name=='profile.jsonl':
                raise PermissionError('test access denied')
            return original(path,*args,**kwargs)
        with patch.object(Path,'open',guarded_open):
            report=p.analyze_trial(self.path)
        self.assertEqual(report['workers_with_profiles'],0)
        self.assertEqual(report['phase_worker_seconds']['target_wall'],4)
        self.assertTrue(all('cannot read' in warning for warning in report['warnings']))
    def test_manifest_paths(self):
        manifest=self.root/'ablations'/'campaign'/'ablation.json';manifest.parent.mkdir(parents=True)
        manifest.write_text(json.dumps({'runs':[{'experiment':'experiments/example','replicate':3}]}))
        reports=p.analyze(manifest)
        self.assertEqual(reports[0]['replicate'],3)
        self.assertEqual(reports[0]['workers_with_profiles'],2)

if __name__=='__main__':unittest.main()
