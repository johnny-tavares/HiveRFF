"""Compile and check sharing behavior without launching a benchmark."""
import itertools
import json
import os
from pathlib import Path
import subprocess
import tempfile

root = Path(__file__).resolve().parent
source = Path(os.environ.get('AFL_SOURCE_DIR', '/opt/sched-fuzz/AFL-2.57b'))
if not source.is_dir():
    source = root.parent / 'sched-fuzz/AFL-2.57b'
mutator_library = Path(os.environ.get('HIVE_LIBMUTATOR', str(source / 'libmutator.a')))
if not mutator_library.is_file():
    raise SystemExit('Build AFL first, or set AFL_SOURCE_DIR to its built source directory.')

with tempfile.TemporaryDirectory(prefix='hive-sharing-test-') as temporary:
    work = Path(temporary)
    common = ['gcc', '-O2', '-ffunction-sections', '-fdata-sections', '-Wno-pointer-sign',
              '-Wno-discarded-qualifiers', '-iquote', str(source), '-DBIN_PATH="/tmp"',
              '-DDOC_PATH="/tmp"']
    for name in ['test_energy', 'test_sharing']:
        command = common + [str(root / (name + '.c'))]
        if name == 'test_sharing':
            command += [str(mutator_library)]
        subprocess.run(command + ['-Wl,--gc-sections', '-o', str(work/name), '-lm', '-ldl', '-lrt'], check=True)
    subprocess.run(['gcc', '-Wall', '-Wextra', '-Werror', '-O2', str(root/'hivemind.c'),
                    str(root/'test_launcher.c'), '-Wl,--wrap=system,--wrap=chdir,--wrap=execv',
                    '-o', str(work/'test_launcher'), '-lrt'], check=True)
    subprocess.run(['clang++', '-std=c++17', '-fPIC', '-shared', '-I', str(source.parent/'include'),
                    '-I', str(source.parent), str(root/'libsched.cpp'), '-ldl', '-pthread', '-msse4.2',
                    '-o', str(work/'libsched.so')], check=True)
    subprocess.run(['gcc', '-Wall', '-Wextra', '-Werror', '-O0', '-fno-omit-frame-pointer',
                    '-fno-pie', '-no-pie', str(root/'test_context_identity.c'), '-ldl',
                    '-o', str(work/'test_context_identity')], check=True)
    identities = []
    for _ in range(8):
        result = subprocess.run([str(work/'test_context_identity'), str(work/'libsched.so')],
                                check=True, stdout=subprocess.PIPE, universal_newlines=True)
        identities.append(tuple(map(int, result.stdout.split())))
    assert len(set(identities)) == 1
    assert identities[0][0] != identities[0][1]
    energy = work/'energy'; energy.mkdir()
    subprocess.run([str(work/'test_energy'), str(energy)], check=True)
    for line in (energy/'energy_decisions.jsonl').read_text().splitlines():
        event = json.loads(line)
        assert 'selected_frequency_count' in event and event['frequency_mode'] in ('global','local')
    events=[json.loads(line) for line in (energy/'energy_decisions.jsonl').read_text().splitlines()]
    assert len(events)==1001 and events[-1]['decision_index']==2000
    assert any(e['selected_would_pass'] and e['assigned_energy']>0 for e in events)
    assert any(not e['selected_would_pass'] and not e['local_would_pass'] and e['local_policy_would_pass'] for e in events)
    metrics=json.loads((energy/'hive_metrics.json').read_text())
    assert metrics['schema_version']==6 and metrics['frequency_policy']=='population_mean_v1'
    assert metrics['shared_rejections_local_policy_would_pass']>0
    assert metrics['shared_passes_local_policy_would_reject']>0
    for frequency, novelty in itertools.product(['global','local'], ['shared','local']):
        output = work/(frequency+'-'+novelty); output.mkdir()
        subprocess.run([str(work/'test_sharing'),frequency,novelty,str(output)],check=True)
        metrics=json.loads((output/'hive_metrics.json').read_text())
        assert metrics['frequency_mode']==frequency and metrics['novelty_mode']==novelty
        for sync in ['on','off']:
            env=dict(os.environ,HIVE_FREQUENCY_MODE=frequency,HIVE_NOVELTY_MODE=novelty,
                     HIVE_AFL_SYNC=sync,WORKERS='2',HIVE_SEED_BASE='400',
                     HIVE_OUTPUT_DIR='/tmp/test-output',TARGET_PROG='/tmp/target')
            subprocess.run([str(work/'test_launcher')],env=env,check=True,stdout=subprocess.DEVNULL)
    for key,value in [('HIVE_FREQUENCY_MODE','typo'),('HIVE_NOVELTY_MODE','typo'),
                      ('HIVE_AFL_SYNC','typo'),('WORKERS','0'),('HIVE_SEED_BASE','2147483647')]:
        invalid=dict(env); invalid[key]=value
        result=subprocess.run([str(work/'test_launcher')],env=invalid,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        assert result.returncode != 0
    print('PASS: stable cross-process event identities, distinct call sites, scoring, JSON, all four process-sharing combinations, eight launch modes, invalid settings.')
