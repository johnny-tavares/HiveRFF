import contextlib
import io
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import tempfile
import unittest

import replay_crashes as replay
from machine_conditions import ConfigurationAudit, observe_trial


class MachineAudit(unittest.TestCase):
    def sample(self, maximum='1200000', current='400000'):
        return {'cpufreq': {'policy0': {'scaling_max_freq': maximum,
                'scaling_cur_freq': current, 'scaling_governor': 'powersave'}},
                'allowed_cpus': [0, 1], 'cgroup_v2': {'cpu.max': 'max 100000'}}

    def test_current_frequency_ignored(self):
        a = ConfigurationAudit(); a.observe(self.sample(), 'before')
        a.observe(self.sample(current='1100000'), 'after')
        self.assertEqual(a.result()['status'], 'stable_observed')

    def test_transient_limit_change_and_revert_retained(self):
        a = ConfigurationAudit()
        for limit in ['1200000', '4800000', '1200000']:
            a.observe(self.sample(maximum=limit), limit)
        self.assertEqual(a.result()['change_count'], 2)
        self.assertFalse(a.result()['timing_configuration_consistent'])

    def test_missing_is_not_stable(self):
        a = ConfigurationAudit(); a.observe({}, 'before'); a.observe({}, 'after')
        self.assertIsNone(a.result()['timing_configuration_consistent'])
        a.observe(self.sample(), 'present'); a.observe({}, 'missing')
        self.assertEqual(a.result()['status'], 'changed')

    def test_timeline_change_detected(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            (directory / 'timeline.jsonl').write_text(json.dumps({'elapsed_sec': 1,
                'machine': self.sample(maximum='4800000')}) + '\n')
            a = ConfigurationAudit()
            observe_trial(a, directory, {'machine_before': self.sample(), 'machine_after': self.sample()})
            self.assertEqual(a.result()['change_count'], 2)

    def test_partial_timeline_cannot_be_reported_stable(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            (directory / 'timeline.jsonl').write_text('{partial')
            a = ConfigurationAudit()
            observe_trial(a, directory, {'machine_before': self.sample(), 'machine_after': self.sample()})
            self.assertEqual(a.result()['status'], 'incomplete')
            self.assertIsNone(a.result()['timing_configuration_consistent'])

    def test_quota_and_affinity_changes(self):
        a = ConfigurationAudit(); sample = self.sample(); a.observe(sample, 'before')
        sample['cgroup_v2']['cpu.max'] = '100000 100000'; sample['allowed_cpus'] = [0]
        a.observe(sample, 'after')
        self.assertEqual(a.result()['change_count'], 2)


class Signatures(unittest.TestCase):
    def test_assertion_site_retained(self):
        a = replay.signature("target: file.c:12: main: Assertion `x == 0' failed.", -6)
        b = replay.signature("other: file.c:12: main: Assertion `x == 0' failed.", -6)
        c = replay.signature("target: file.c:13: main: Assertion `x == 0' failed.", -6)
        self.assertEqual(a['signature'], b['signature'])
        self.assertNotEqual(a['signature'], c['signature'])

    def test_sanitizer_addresses_normalized_offsets_preserved(self):
        text = '==42==ERROR: AddressSanitizer: heap-use-after-free on address 0xdead\n #0 0x123 (/target+0x456)\n'
        a = replay.signature(text, -6)
        b = replay.signature(text.replace('42', '99').replace('0x123', '0xabcd').replace('0xdead', '0xbeef'), -6)
        c = replay.signature(text.replace('+0x456', '+0x789'), -6)
        self.assertEqual(a['signature'], b['signature'])
        self.assertNotEqual(a['signature'], c['signature'])

    def test_unresolved_signal_is_not_distinct_bug(self):
        s = replay.signature('', -11)
        self.assertEqual(s['kind'], 'unclassified_signal')
        self.assertNotIn('signature', s)
        self.assertEqual(replay.signature('ERROR: object cannot be preloaded', -6)['kind'], 'replay_error')
        self.assertEqual(replay.signature('', 3)['kind'], 'nonzero_exit')


@unittest.skipUnless(shutil.which('gcc'), 'native fixture requires gcc')
class NativeReplay(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        src = self.root / 'target.c'
        src.write_text(r'''#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
int main(void) {
  assert(getenv("__AFL_SHM_ID") == NULL);
  assert(getenv("HIVEMIND_SHM") == NULL);
  assert(getchar() == 'Q');
  FILE *f = fopen(getenv("SCHEDULE"), "r"); assert(f);
  int mode = fgetc(f); fclose(f);
  if (mode == 'A') { assert(0 && "target bug"); }
  if (mode == 'T') { if (fork() == 0) { sleep(30); } sleep(30); }
  if (mode == 'S') { raise(SIGSEGV); }
  if (mode == 'E') { return 7; }
  if (mode == 'O') { for (int i=0; i<100000; i++) putchar('x'); }
  return 0;
}
''')
        self.target = self.root / 'target.afl'
        subprocess.run(['gcc', '-O0', str(src), '-o', str(self.target)], check=True)
        src.write_text('int fixture(void) { return 1; }\n')
        self.preload = self.root / 'libsched.so'
        subprocess.run(['gcc', '-shared', '-fPIC', str(src), '-o', str(self.preload)], check=True)
        self.record = {'environment': {'TARGET_PROG': str(self.target), 'AFL_PRELOAD': str(self.preload)},
                       'worker_seeds': {'worker_0': 42}}
        self.input = self.root / 'input'; self.input.write_bytes(b'Q')
        self.schedule = self.root / 'case.sched'

    def case(self, mode, attempts=2):
        self.schedule.write_text(mode)
        return replay.replay_case({'worker': 'worker_0', 'schedule': self.schedule, 'input': self.input},
                                  self.record, str(self.target), str(self.preload), attempts, 0.15)

    def test_real_abort_and_normal(self):
        result = self.case('A')
        self.assertEqual(result['reproduction'], 'all_attempts_failed')
        self.assertEqual(result['failure_attempts'], 2)
        self.assertEqual(replay.summarize([result])['diagnostic_signature_count'], 1)
        self.assertEqual(self.case('N')['reproduction'], 'not_reproduced')

    def test_timeout_signal_exit_and_output_bound(self):
        self.assertEqual(self.case('T', 1)['attempts'][0]['classification']['kind'], 'timeout')
        self.assertEqual(self.case('S', 1)['attempts'][0]['classification']['kind'], 'unclassified_signal')
        self.assertEqual(self.case('E', 1)['reproduction'], 'incomplete')
        output = self.case('O', 1)['attempts'][0]
        self.assertEqual(output['classification']['kind'], 'output_incomplete')
        self.assertLessEqual(len(output['output']['stdout']['text']), replay.OUTPUT_LIMIT)

    def test_missing_input_not_replayed(self):
        result = replay.replay_case({'worker': 'worker_0', 'schedule': self.schedule, 'input': None},
                                   self.record, str(self.target), str(self.preload), 3, 1)
        self.assertEqual(result['reproduction'], 'incomplete')
        self.assertEqual(result['attempts'], [])

    def campaign(self):
        campaign = self.root / 'out/ablations/campaign'; (campaign / 'build').mkdir(parents=True)
        experiment = self.root / 'out/experiments/experiment'; experiment.mkdir(parents=True)
        trial = experiment / 'trial-001'
        queue = trial / 'afl/worker_0/queue'; queue.mkdir(parents=True)
        (queue / 'id:000000,orig:seed').write_bytes(b'Q')
        (queue / 'id:000001,orig:other').write_bytes(b'X')
        scheds = trial / 'afl/worker_0/scheds/id:000000'; scheds.mkdir(parents=True)
        (scheds / 'crash-000001:00000002.sched').write_text('A')
        record = dict(self.record, crash_files=['worker_0/scheds/id:000000/crash-000001:00000002.sched'])
        replay.save(trial / 'record.json', record)
        replay.save(experiment / 'experiment.json', {'trials': [{'record': 'trial-001/record.json'}]})
        build = {'build_id': 'fixture', 'runtime_sha256': {str(p): replay.digest(p) for p in [self.target, self.preload]}}
        replay.save(campaign / 'build/build.json', build)
        replay.save(campaign / 'ablation.json', {'runs': [{'replicate': 1, 'sharing': {'frequency': 'local', 'novelty': 'local'},
                                                        'experiment': 'experiments/experiment'}]})
        return campaign / 'ablation.json'

    def test_campaign_and_runtime_mismatch(self):
        path = self.campaign()
        with contextlib.redirect_stdout(io.StringIO()):
            report_path = replay.replay_campaign(path, maximum=1, attempts=2, timeout=1)
            report = json.loads(report_path.read_text())
            self.assertEqual(report['status'], 'completed')
            self.assertEqual(report['summary']['case_outcomes'], {'all_attempts_failed': 1})
            self.assertIsNone(report['summary']['distinct_bug_count'])
            self.target.write_text('replaced build')
            with self.assertRaisesRegex(RuntimeError, 'original path'):
                replay.replay_campaign(path, maximum=1)

    def test_balanced_sample(self):
        cases = [{'worker': 'worker_' + str(w), 'schedule': Path(str(w) + '-' + str(i))}
                 for w in range(3) for i in range(8)]
        selected = replay.choose(cases, 6)
        self.assertEqual(Counter(c['worker'] for c in selected), {f'worker_{i}': 2 for i in range(3)})


from collections import Counter
if __name__ == '__main__':
    unittest.main()
