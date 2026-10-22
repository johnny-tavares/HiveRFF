import contextlib
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import run_ablation as a

r = a.runner


class Ablation(unittest.TestCase):
    """Exercise the real controller, build guard, manifests and lock with fake binaries."""
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.target = self.root / 'target'
        self.runtime = [self.target, self.root / 'afl-fuzz', self.root / 'libsched.so']
        self.source = self.root / 'source.c'
        self.source.write_text('source revision one')
        self.input = self.root / 'mempair.target'
        self.input.write_text('instrumentation input')
        self.seeds = self.root / 'seeds'
        self.seeds.mkdir()
        (self.seeds / 'hi.txt').write_text('hi')
        self.calls = []
        self.failure = None
        self.build_calls = 0
        self.args = ['--target', str(self.target), '--workers', '2', '--seconds', '1', '--trials', '1']
        self.stack = contextlib.ExitStack()
        self.addCleanup(self.stack.close)
        self.stack.enter_context(patch.object(r, 'OUT_ROOT', self.root / 'out'))
        self.stack.enter_context(patch.object(r, 'runtime_fingerprints', side_effect=lambda:
            {str(p): r.fingerprint(p) for p in self.runtime}))
        self.stack.enter_context(patch.object(r, 'source_fingerprints', side_effect=lambda:
            {str(self.source): r.fingerprint(self.source)}))
        self.stack.enter_context(patch.object(r, 'seed_fingerprints', side_effect=lambda:
            {str(p): r.fingerprint(p) for p in self.seeds.iterdir()}))
        self.setup = self.stack.enter_context(patch.object(r, 'setup_environment', side_effect=self.fake_build))
        self.stack.enter_context(patch.object(r, 'capture_provenance', side_effect=self.fake_provenance))
        self.stack.enter_context(patch.object(r, 'preflight'))
        self.stack.enter_context(patch.object(r, 'run_trial', side_effect=self.fake_trial))
        self.stack.enter_context(patch.object(r, 'machine_snapshot', return_value={'test_snapshot': True}))
        self.stack.enter_context(contextlib.redirect_stdout(io.StringIO()))

    def fake_build(self, log):
        self.build_calls += 1
        for path in self.runtime:
            path.write_text('built artifact ' + path.name + ' build ' + str(self.build_calls))
        # A second new runner cannot acquire the output lock, including during setup.
        with self.assertRaises(BlockingIOError):
            with r.experiment_lock():
                self.fail('campaign lock was not held during setup')

    def fake_provenance(self, directory):
        copies = directory / 'target_inputs'
        copies.mkdir()
        (copies / self.input.name).write_bytes(self.input.read_bytes())
        return {'period_commit': 'test', 'files': {str(self.input):
            {'sha256': r.fingerprint(self.input), 'copy': 'target_inputs/' + self.input.name}}}

    def fake_trial(self, experiment, number):
        self.calls.append((r.sharing_settings(), r.SEED_BASE))
        self.assertEqual(r.trial_settings(number, experiment)['ALL_RFF'], '1')
        with self.assertRaises(BlockingIOError):
            with r.experiment_lock():
                self.fail('campaign lock was not held during a trial')
        record = {'status': 'budget_completed', 'measurement_complete': True,
                  'worker_abort_reasons': [], 'manager_returncode_after_stop': 0,
                  'workers': {'worker_%d' % i: {'metrics': {'schedule_bitmap_nonempty_returns': 10}}
                              for i in range(r.WORKERS)}}
        if self.failure == 'incomplete':
            record['measurement_complete'] = False
        elif self.failure == 'empty':
            record['workers']['worker_0']['metrics']['schedule_bitmap_nonempty_returns'] = 0
        elif self.failure == 'missing_worker':
            record['workers'].pop('worker_0')
        elif self.failure == 'worker_abort':
            record['worker_abort_reasons'] = ['test abort']
        elif self.failure == 'manager':
            record['manager_returncode_after_stop'] = 1
        elif self.failure == 'failed':
            record['status'] = 'failed'
        directory = experiment / ('trial-%03d' % number)
        directory.mkdir()
        r.save_json(directory / 'record.json', record)
        if self.failure == 'runtime':
            self.runtime[1].write_text('changed during trial')
        elif self.failure == 'source':
            self.source.write_text('changed during trial')
        elif self.failure == 'input':
            self.input.write_text('changed during trial')
        elif self.failure == 'seed':
            (self.seeds / 'added-seed').write_text('new seed')
        elif self.failure == 'interrupt':
            raise KeyboardInterrupt
        return record

    def manifest(self):
        return json.loads(next(r.OUT_ROOT.glob('ablations/*/ablation.json')).read_text())

    def test_matched_seeds_and_balanced_positions(self):
        with contextlib.redirect_stdout(io.StringIO()) as output:
            self.assertEqual(a.main(['--dry-run']), 0)
        lines = [line for line in output.getvalue().splitlines() if line.startswith('Replicate')]
        self.assertEqual(len(lines), 16)
        for replicate in range(4):
            group = lines[4*replicate:4*replicate+4]
            self.assertTrue(all('--seed-base %d ' % (1000+16*replicate) in line for line in group))
            self.assertTrue(all('--afl-sync on' in line and '--all-rff on' in line for line in group))
            for frequency, novelty in a.MODES:
                self.assertEqual(sum('--frequency %s --novelty %s' % (frequency, novelty) in line
                                     for line in group), 1)
        for position in range(4):
            self.assertEqual(len({line.split('--frequency ')[1] for line in lines[position::4]}), 4)
        self.setup.assert_not_called()
        self.assertFalse(r.OUT_ROOT.exists())

    def test_one_build_reused_for_all_sixteen_runs(self):
        self.assertEqual(a.main(self.args + ['--trials', '4']), 0)
        self.assertEqual(self.build_calls, 1)
        self.assertEqual(len(self.calls), 16)
        manifest = self.manifest()
        self.assertEqual(manifest['status'], 'completed')
        self.assertNotIn('active_run', manifest)
        self.assertEqual({run['build_id'] for run in manifest['runs']}, {manifest['build_id']})
        build = json.loads(Path(manifest['build_manifest']).read_text())
        for path, copy in build['archived_runtime'].items():
            self.assertEqual(r.fingerprint(Path(build['directory']) / copy), build['runtime_sha256'][path])
        for run in manifest['runs']:
            experiment = r.OUT_ROOT / run['experiment']
            data = json.loads((experiment / 'experiment.json').read_text())
            self.assertTrue(data['build_reused'])
            self.assertEqual(data['build_verification_before'], 'passed')
            self.assertEqual(data['build_verification_after'], 'passed')
            self.assertEqual(data['runtime_sha256'], build['runtime_sha256'])
            self.assertEqual((experiment / 'target_inputs' / self.input.name).read_text(), self.input.read_text())
        for replicate in range(4):
            group = self.calls[replicate*4:replicate*4+4]
            self.assertEqual({seed for sharing, seed in group}, {1000+2*replicate})
        # The lock is released at the end.
        with r.experiment_lock():
            pass

    def test_incomplete_metrics_stop_before_next_arm(self):
        self.check_rejected('incomplete', 'Incomplete metrics')

    def test_empty_feedback_stops_before_next_arm(self):
        self.check_rejected('empty', 'Missing nonempty schedule feedback')

    def test_missing_worker_stops_before_next_arm(self):
        self.check_rejected('missing_worker', 'Missing nonempty schedule feedback')

    def test_worker_abort_stops_before_next_arm(self):
        self.check_rejected('worker_abort', 'Incomplete metrics')

    def test_manager_failure_stops_before_next_arm(self):
        self.check_rejected('manager', 'Incomplete metrics')

    def test_trial_failure_stops_before_next_arm(self):
        self.check_rejected('failed', 'completed_with_failures')

    def check_rejected(self, failure, message):
        self.failure = failure
        with self.assertRaisesRegex(RuntimeError, message):
            a.main(self.args)
        self.assertEqual(len(self.calls), 1)
        manifest = self.manifest()
        self.assertEqual(manifest['status'], 'failed')
        self.assertEqual(len(manifest['runs']), 1)
        self.assertIn('machine_after', manifest)

    def test_runtime_drift_preserves_trial_and_stops(self):
        self.check_drift('runtime', 'Runtime artifacts changed')

    def test_source_drift_preserves_trial_and_stops(self):
        self.check_drift('source', 'Sources changed')

    def test_input_drift_preserves_trial_and_stops(self):
        self.check_drift('input', 'Build input changed')

    def test_seed_addition_preserves_trial_and_stops(self):
        self.check_drift('seed', 'Seed corpus changed')

    def check_drift(self, failure, message):
        self.failure = failure
        with self.assertRaisesRegex(RuntimeError, message):
            a.main(self.args)
        self.assertEqual(len(self.calls), 1)
        self.assertEqual(self.manifest()['status'], 'failed')
        experiment = next(r.OUT_ROOT.glob('experiments/*/experiment.json'))
        data = json.loads(experiment.read_text())
        self.assertEqual(data['status'], 'failed')
        self.assertEqual(len(data['trials']), 1)
        self.assertTrue((experiment.parent / data['trials'][0]['record']).is_file())
        self.assertNotIn('build_verification_after', data)

    def test_interrupt_records_interrupted_status(self):
        self.failure = 'interrupt'
        self.assertEqual(a.main(self.args), 130)
        self.assertEqual(self.manifest()['status'], 'interrupted')
        self.assertEqual(len(self.calls), 1)

    def test_missing_build_artifact_stops_before_trials(self):
        self.runtime.append(self.root / 'missing')
        original = self.fake_build
        def incomplete(log):
            original(log)
            self.runtime[-1].unlink()
        self.setup.side_effect = incomplete
        with self.assertRaisesRegex(RuntimeError, 'all required runtime artifacts'):
            a.main(self.args)
        self.assertEqual(self.calls, [])
        self.assertEqual(self.manifest()['status'], 'failed')


class MachineObservations(unittest.TestCase):
    def test_available_machine_counters_and_cgroup(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            proc, sysfs = root / 'proc', root / 'sys'
            files = {
                'proc/loadavg': '1.25 2.5 3.0 1/123 456',
                'proc/stat': 'cpu  10 20 30 40 50 60 70 80 90 100\ncpu0 1 2 3',
                'proc/meminfo': 'MemTotal: 8192 kB\nMemAvailable: 4096 kB\nSwapFree: 0 kB',
                'proc/sys/kernel/osrelease': 'test-kernel',
                'proc/self/cgroup': '0::/test-group',
                'sys/fs/cgroup/test-group/cpu.max': '200000 100000',
                'sys/fs/cgroup/test-group/cpu.stat': 'usage_usec 123\nnr_throttled 2',
                'sys/devices/system/cpu/cpufreq/policy0/scaling_governor': 'powersave',
                'sys/devices/system/cpu/cpufreq/policy0/scaling_cur_freq': '1200000',
            }
            for path, value in files.items():
                location = root / path
                location.parent.mkdir(parents=True, exist_ok=True)
                location.write_text(value)
            data = r.machine_snapshot(proc, sysfs)
            self.assertEqual(data['load_average'], [1.25, 2.5, 3.0])
            self.assertEqual(data['cpu_ticks']['idle'], 40)
            self.assertEqual(data['cpu_ticks']['guest'], 90)
            self.assertEqual(data['memory_kib']['MemAvailable'], 4096)
            self.assertEqual(data['kernel_release'], 'test-kernel')
            self.assertEqual(data['cgroup_v2']['cpu.max'], '200000 100000')
            self.assertIsNone(data['cgroup_v2']['memory.current'])
            self.assertEqual(data['cpufreq']['policy0']['scaling_governor'], 'powersave')
            self.assertIsNone(data['cpufreq']['policy0']['cpuinfo_cur_freq'])
            self.assertGreaterEqual(data['collection_duration_ns'], 0)

    def test_missing_and_malformed_optional_data(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            for path, contents in [('loadavg', 'bad data'), ('stat', 'cpu bad'),
                                   ('meminfo', 'MemTotal: bad\nMemAvailable:')]:
                (root / path).write_text(contents)
            (root / 'self').mkdir()
            (root / 'self/cgroup').write_text('0::/../../outside')
            with patch.object(r.os, 'sched_getaffinity', side_effect=OSError):
                data = r.machine_snapshot(root, root / 'missing-sys')
            for field in ('load_average', 'cpu_ticks', 'memory_kib', 'cpufreq', 'cgroup_v2', 'allowed_cpus'):
                self.assertIsNone(data[field])
            with patch.object(Path, 'read_text', side_effect=PermissionError):
                self.assertIsNone(r.read_optional(root / 'loadavg'))

    def test_core_pattern_rejected_without_changing_host(self):
        with patch.object(r, 'read_optional', return_value='|systemd-coredump'):
            with self.assertRaisesRegex(RuntimeError, 'core_pattern'):
                r.preflight()

    def test_no_rff_matches_runtime_boolean_semantics(self):
        with patch.object(r, 'read_optional', return_value='core'):
            for value in ('1', '', 'false'):
                with patch.dict(os.environ, {'NO_RFF': value}):
                    with self.assertRaisesRegex(RuntimeError, 'NO_RFF'):
                        r.preflight()
            with patch.dict(os.environ, {'NO_RFF': '0'}):
                r.preflight()


if __name__ == '__main__':
    unittest.main()
