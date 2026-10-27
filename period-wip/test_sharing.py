"""Compile and check sharing behavior without launching a benchmark."""
import itertools
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile

root = Path(__file__).resolve().parent
source = Path(os.environ.get('AFL_SOURCE_DIR', '/opt/sched-fuzz/AFL-2.57b'))
if not source.is_dir():
    source = root.parent / 'sched-fuzz/AFL-2.57b'
mutator_override = os.environ.get('HIVE_LIBMUTATOR')

with tempfile.TemporaryDirectory(prefix='hive-sharing-test-') as temporary:
    work = Path(temporary)
    if mutator_override:
        mutator_library = Path(mutator_override)
        if not mutator_library.is_file():
            raise SystemExit('HIVE_LIBMUTATOR does not name a file: ' + mutator_override)
    else:
        mutator_source = root/'mutator.zig'
        if not mutator_source.is_file():
            raise SystemExit('Missing mounted mutator.zig; set HIVE_LIBMUTATOR explicitly.')
        shutil.copy2(str(mutator_source), str(work/'mutator.zig'))
        subprocess.run(['zig', 'build-lib', '-lc', '-femit-h', '-fcompiler-rt', 'mutator.zig'],
                       cwd=str(work), check=True)
        mutator_library = work/'libmutator.a'
        if not mutator_library.is_file():
            raise SystemExit('Zig did not produce the temporary libmutator.a.')
    subprocess.run(['python3',str(root/'test_preprocess.py')],
                   env=dict(os.environ,HIVE_LIBMUTATOR=str(mutator_library),AFL_SOURCE_DIR=str(source)),check=True)
    common = ['gcc', '-O2', '-ffunction-sections', '-fdata-sections', '-Wno-pointer-sign',
              '-Wno-discarded-qualifiers', '-iquote', str(source), '-DBIN_PATH="/tmp"',
              '-DDOC_PATH="/tmp"']
    for name in ['test_energy', 'test_sharing', 'test_profile']:
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
    profile = work/'profile'; profile.mkdir()
    subprocess.run([str(work/'test_profile'),str(profile)],check=True)
    profile_rows=[json.loads(line) for line in (profile/'profile.jsonl').read_text().splitlines()]
    assert len(profile_rows)==2 and profile_rows[0]['kind']=='selection'
    assert profile_rows[1]['kind']=='execution' and not profile_rows[1]['interrupted']
    profile_metrics=json.loads((profile/'hive_metrics.json').read_text())
    assert profile_metrics['profiling_enabled'] and profile_metrics['profile_dropped_rows']==1
    assert profile_metrics['profile_selection_calls']==1 and profile_metrics['profile_selection_ns']>0
    energy = work/'energy'; energy.mkdir()
    subprocess.run([str(work/'test_energy'), str(energy)], check=True)
    for line in (energy/'energy_decisions.jsonl').read_text().splitlines():
        event = json.loads(line)
        assert 'selected_frequency_count' in event and event['frequency_mode'] in ('global','local')
        assert {'candidate_energy', 'local_policy_energy', 'assigned_energy'} <= set(event)
    events=[json.loads(line) for line in (energy/'energy_decisions.jsonl').read_text().splitlines()]
    assert len(events)==1001 and events[-1]['decision_index']==2000
    assert any(not e['selected_downweighted'] and e['assigned_energy']>0 for e in events)
    assert any(e['selected_downweighted'] and 0 < e['assigned_energy'] < e['candidate_energy'] for e in events)
    assert all(4*e['assigned_energy']>=3*e['candidate_energy'] for e in events)
    metrics=json.loads((energy/'hive_metrics.json').read_text())
    assert metrics['schema_version']==11 and metrics['frequency_policy']=='guarded_frequency_energy_v4'
    assert metrics['shared_downweights_local_would_full']>0
    assert metrics['shared_full_local_would_downweight']>0
    assert metrics['frequency_downweighted_decisions']>0
    assert metrics['frequency_energy_removed']>0
    assert metrics['frequency_assigned_energy']<metrics['frequency_candidate_energy']
    assert metrics['frequency_candidate_energy']==metrics['frequency_assigned_energy']+metrics['frequency_energy_removed']
    assert 4*metrics['frequency_assigned_energy']>=3*metrics['frequency_candidate_energy']
    assert metrics['frequency_decisions']==metrics['frequency_downweighted_decisions']+metrics['frequency_full_energy_decisions']+metrics['zero_energy_other']
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
    failure_env=dict(env,TEST_FAIL_WORKER='1')
    failed=subprocess.run([str(work/'test_launcher')],env=failure_env,
                          stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=5)
    assert failed.returncode!=0
    for key,value in [('HIVE_FREQUENCY_MODE','typo'),('HIVE_NOVELTY_MODE','typo'),
                      ('HIVE_AFL_SYNC','typo'),('WORKERS','0'),('HIVE_SEED_BASE','2147483647')]:
        invalid=dict(env); invalid[key]=value
        result=subprocess.run([str(work/'test_launcher')],env=invalid,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        assert result.returncode != 0
    print('PASS: stable cross-process event identities, distinct call sites, scoring, JSON, all four process-sharing combinations, eight launch modes, invalid settings.')
