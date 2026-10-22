import importlib.util
import json
import tempfile
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location('runner', str(Path(__file__).with_name('run_hiverff.py')))
r = importlib.util.module_from_spec(spec)
spec.loader.exec_module(r)

class Records(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        r.FREQUENCY_MODE = 'global'
        r.NOVELTY_MODE = 'shared'
        r.AFL_SYNC = 'on'
        r.ALL_RFF_MODE = 'inherit'
        r.SEED_BASE = 100
        r.NUM_TRIALS = 1
        r.WORKERS = 1
        r.TIME_BUDGET = .2
        r.POLL_SECONDS = .01
        r.MODE = 'SPEED'
        self.fake = self.root / 'manager'
        r.MANAGER = str(self.fake)
    def tearDown(self):
        self.tmp.cleanup()
    def manager(self, behavior):
        self.fake.write_text('#!/usr/bin/env python3\nimport os, time\nfrom pathlib import Path\np=Path(os.environ["HIVE_OUTPUT_DIR"])/"worker_0"\np.mkdir()\n(p/"fuzzer_stats").write_text("start_time : 123\\nexecs_done : 7\\n")\n(p/"num_scheds.txt").write_text("7")\n'+behavior)
        self.fake.chmod(0o755)
    def test_crash_preserved_across_trials(self):
        self.manager('(p/"crashes").mkdir()\n(p/"crashes"/"id:000000").write_text("crash")\ntime.sleep(10)\n')
        one=r.run_trial(self.root, 1)
        two=r.run_trial(self.root, 2)
        self.assertEqual(one['status'], 'crash_found')
        self.assertEqual(two['legacy_mutations_generated'], 7)
        self.assertTrue((self.root/'trial-001/afl/worker_0/crashes/id:000000').exists())
        self.assertEqual(one['worker_seeds']['worker_0'], 101)
        self.assertIsNotNone(one['first_crash_observed_sec'])
    def test_timeout_retained(self):
        self.manager('time.sleep(10)\n')
        result=r.run_trial(self.root, 1)
        self.assertEqual(result['status'], 'timeout')
        self.assertIsNone(result['first_crash_observed_sec'])
        self.assertEqual(json.loads((self.root/'trial-001/record.json').read_text())['status'], 'timeout')
    def test_early_exit_is_failure_even_zero(self):
        self.manager('raise SystemExit(0)\n')
        result=r.run_trial(self.root, 1)
        self.assertEqual(result['status'], 'failed')
        self.assertEqual(result['manager_exit_code_before_stop'], 0)
    def test_launch_failure_and_missing_counts(self):
        result=r.run_trial(self.root, 1)
        self.assertEqual(result['status'], 'failed')
        self.assertIsNone(result['legacy_mutations_generated'])
    def test_interrupt_is_saved(self):
        from unittest.mock import patch
        self.manager('time.sleep(10)\n')
        real_sleep = r.time.sleep
        calls = []
        def interrupt_once(seconds):
            if not calls:
                calls.append(True)
                raise KeyboardInterrupt
            real_sleep(seconds)
        with patch.object(r.time, 'sleep', side_effect=interrupt_once):
            with self.assertRaises(KeyboardInterrupt):
                r.run_trial(self.root, 1)
        record=json.loads((self.root/'trial-001/record.json').read_text())
        self.assertEqual(record['status'], 'interrupted')

    def test_metrics_completeness_and_legacy_meaning(self):
        worker=self.root/'worker_0'
        worker.mkdir()
        (worker/'num_scheds.txt').write_text('10')
        incomplete=r.snapshot(self.root)
        self.assertFalse(incomplete['all_worker_metrics_final'])
        self.assertIsNone(incomplete['totals']['schedule_executions_completed'])
        self.assertEqual(incomplete['legacy_mutations_generated'],10)
        metrics={'schema_version':2, 'final':False, 'published_monotonic_ns':r.time.monotonic_ns(),
                 'mutations_generated':10, 'schedule_executions_started':10,
                 'schedule_executions_completed':9, 'schedule_executions_interrupted':1}
        (worker/'hive_metrics.json').write_text(json.dumps(metrics))
        observed=r.snapshot(self.root)
        self.assertEqual(observed['totals']['schedule_executions_completed'],9)
        self.assertFalse(observed['all_worker_metrics_final'])
        metrics['final']=True
        (worker/'hive_metrics.json').write_text(json.dumps(metrics))
        self.assertTrue(r.snapshot(self.root)['all_worker_metrics_final'])

    def test_population_metrics_do_not_sum_global_snapshots(self):
        r.WORKERS=2
        for index in range(2):
            worker=self.root/('worker_%d'%index);worker.mkdir()
            (worker/'hive_metrics.json').write_text(json.dumps({
                'schema_version':6, 'final':True,
                'local_frequency_observations':10, 'selected_frequency_observations':20,
                'selected_frequency_trace_buckets':4,
                'shared_rejections_local_policy_would_pass':index+1,
                'shared_passes_local_policy_would_reject':0, 'frequency_decisions':5}))
        snapshot=r.snapshot(self.root)
        self.assertEqual(snapshot['totals']['local_frequency_observations'],20)
        self.assertEqual(snapshot['totals']['shared_rejections_local_policy_would_pass'],3)
        self.assertNotIn('selected_frequency_observations',snapshot['totals'])
        self.assertNotIn('selected_frequency_trace_buckets',snapshot['totals'])

    def test_diagnostic_environment_is_recorded(self):
        from unittest.mock import patch
        self.manager('time.sleep(10)\n')
        with patch.dict(r.os.environ, {'ALL_RFF':'1'}):
            result=r.run_trial(self.root,1)
        self.assertEqual(result['environment']['ALL_RFF'],'1')

    def test_shutdown_flush_is_retained(self):
        r.MODE='THROUGHPUT'
        self.manager('import signal, json\ndef flush(sig, frame):\n (p/"hive_metrics.json").write_text(json.dumps({"schema_version":2,"final":True,"published_monotonic_ns":time.monotonic_ns(),"mutations_generated":7,"schedule_executions_completed":6}))\n raise SystemExit(0)\nsignal.signal(signal.SIGTERM,flush)\ntime.sleep(10)\n')
        result=r.run_trial(self.root,1)
        self.assertTrue(result['measurement_complete'])
        self.assertEqual(result['totals']['schedule_executions_completed'],6)
        self.assertFalse(result['at_stop_request']['all_worker_metrics_final'])
        self.assertEqual(result['manager_returncode_after_stop'],0)

    def test_throughput_budget(self):
        r.MODE='THROUGHPUT'
        self.manager('time.sleep(10)\n')
        result=r.run_trial(self.root, 1)
        self.assertEqual(result['status'], 'budget_completed')
        self.assertEqual(result['environment']['MASK'], '0x3FFF')
        self.assertIn('collection_duration_ns', result['machine_before'])
        self.assertIn('collection_duration_ns', result['machine_after'])
        timeline = [json.loads(line) for line in (self.root/'trial-001/timeline.jsonl').read_text().splitlines()]
        self.assertTrue(timeline)
        self.assertIn('collection_duration_ns', timeline[0]['machine'])

    def test_explicit_all_rff_overrides_inherited_environment(self):
        from unittest.mock import patch
        self.manager('time.sleep(10)\n')
        with patch.dict(r.os.environ, {'ALL_RFF': '0'}):
            r.configure_cli(['--all-rff', 'on'])
            result = r.run_trial(self.root, 1)
        self.assertEqual(result['environment']['ALL_RFF'], '1')
        r.configure_cli(['--all-rff', 'off'])
        self.assertEqual(r.trial_settings(1, self.root)['ALL_RFF'], '0')
    def test_setup_failure_record_and_legacy_preservation(self):
        r.OUT_ROOT=self.root/'out'
        legacy=r.OUT_ROOT/'worker_0'
        legacy.mkdir(parents=True)
        (legacy/'old').write_text('keep')
        original=r.setup_environment
        def fail(log):
            raise RuntimeError('build failed')
        r.setup_environment=fail
        try:
            with self.assertRaises(RuntimeError): r.main()
        finally:
            r.setup_environment=original
        records=list(r.OUT_ROOT.glob('experiments/*/experiment.json'))
        self.assertEqual(json.loads(records[0].read_text())['status'], 'failed')
        self.assertEqual((legacy/'old').read_text(),'keep')

    def test_cli_local_control_and_paired_seeds(self):
        r.configure_cli(['--frequency','local','--novelty','local','--afl-sync','off',
                         '--seconds','60','--workers','16','--trials','2','--seed-base','400',
                         '--target','/workdir/PERIOD/evaluation/CS/twostage_100/twostage_100_bad'])
        settings = r.trial_settings(2, self.root)
        self.assertEqual(settings['HIVE_FREQUENCY_MODE'], 'local')
        self.assertEqual(settings['HIVE_NOVELTY_MODE'], 'local')
        self.assertEqual(settings['HIVE_AFL_SYNC'], 'off')
        self.assertEqual(settings['HIVE_SEED_BASE'], '416')
        self.assertEqual(settings['AFL_SKIP_CPUFREQ'], '1')
        self.assertEqual(r.TIME_BUDGET, 60)
        self.assertEqual(r.TARGET_PROG, '/workdir/PERIOD/evaluation/CS/twostage_100/twostage_100_bad')

    def test_throughput_repeats_and_records_modes(self):
        from unittest.mock import patch
        r.MODE = 'THROUGHPUT'
        r.NUM_TRIALS = 2
        r.FREQUENCY_MODE = 'local'
        r.AFL_SYNC = 'off'
        r.OUT_ROOT = self.root / 'out'
        self.manager('time.sleep(10)\n')
        with patch.object(r, 'setup_environment'), patch.object(r, 'capture_provenance', return_value={}):
            r.main()
        manifest_path = next(r.OUT_ROOT.glob('experiments/*/experiment.json'))
        manifest = json.loads(manifest_path.read_text())
        self.assertEqual(len(manifest['trials']), 2)
        self.assertEqual(manifest['sharing'], {'frequency':'local','novelty':'shared','afl_sync':'off'})
        second = json.loads((manifest_path.parent/'trial-002/record.json').read_text())
        self.assertEqual(second['worker_seeds']['worker_0'],102)
        self.assertEqual(second['environment']['HIVE_AFL_SYNC'],'off')

    def test_target_provenance_copies_inputs(self):
        from unittest.mock import patch
        target=self.root/'target'
        source=Path(str(target)+'.c'); source.write_text('int main() {}')
        pairs=self.root/'mempair.target'; pairs.write_text('memory pairs')
        with patch.object(r,'TARGET_PROG',str(target)), patch.object(r.subprocess,'run') as git:
            git.return_value.returncode=0
            git.return_value.stdout='abc123\n'
            data=r.capture_provenance(self.root)
        self.assertEqual(data['period_commit'],'abc123')
        self.assertEqual(data['files'][str(source)]['sha256'],r.fingerprint(source))
        self.assertEqual((self.root/'target_inputs/target.c').read_text(),source.read_text())

unittest.main()
