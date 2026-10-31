"""Replay a worker-balanced sample of saved crash schedules after timed fuzzing.

Uses verified original runtime paths: relocating modules changes context IDs.
Failure signatures are diagnostic groups, never counts of distinct bugs.
"""
import argparse
from collections import Counter, defaultdict
from contextlib import nullcontext
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import resource
import shutil
import signal
import subprocess
import tempfile
import threading
import time
import uuid

# Explicit target/scheduler controls only; never inherit AFL IPC or a live preload.
REPLAY_ENV = ('ALL_RFF', 'NO_RFF', 'NO_POS', 'POS_ONLY', 'TIMER_MAX',
              'THREAD_AFFINITY', 'PRIORITY_CHANGE_FREQ_PCT', 'ATOMIC',
              'JSON_SCHEDULE', 'ASAN_OPTIONS', 'UBSAN_OPTIONS', 'TSAN_OPTIONS',
              'MSAN_OPTIONS', 'LD_LIBRARY_PATH', 'MASK')
OUTPUT_LIMIT = 65536


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def save(path, data):
    tmp = path.with_suffix('.tmp')
    tmp.write_text(json.dumps(data, indent=2) + '\n')
    tmp.replace(path)


def signature(text, returncode):
    text = re.sub(r'\x1b\[[0-9;?]*[A-Za-z]', '', text)
    # Loader/preload failures must not masquerade as target failures.
    if any(s in text for s in ('cannot be preloaded', 'error while loading shared libraries',
                               'failed to open file', 'ASan runtime does not come first')):
        return {'kind': 'replay_error', 'evidence': text[:2000]}
    assertion = re.search(r"([^\n]*Assertion [^\n]* failed\.)", text)
    sanitizer = re.search(r'(?:ERROR|WARNING): ((?:Address|Memory|Thread|UndefinedBehavior)Sanitizer:[^\n]+)|SUMMARY: ([^\n]*Sanitizer:[^\n]+)', text)
    if returncode == 0:
        return {'kind': 'normal'}
    if assertion:
        evidence = assertion[1]
        # glibc assertion diagnostics prefix executable name, then file:line.
        evidence = re.sub(r'^.*?: (?=[^:]+:\d+:)', '', evidence)
        kind = 'assertion'
    elif sanitizer:
        headline = sanitizer[1] or sanitizer[2]
        headline = re.split(r' on (?:address|unknown address)', headline)[0]
        frames = re.findall(r'^\s*#\d+\s+[^\n]+', text, re.M)[:6]
        evidence = headline + '\n' + '\n'.join(frames)
        evidence = re.sub(r'(#\d+)\s+0x[0-9a-fA-F]+', r'\1 <pc>', evidence)
        evidence = re.sub(r'==\d+==|\b(?:pid|tid)[=: ]+\d+', '<id>', evidence)
        kind = 'sanitizer'
    elif returncode < 0:
        return {'kind': 'unclassified_signal', 'signal': -returncode,
                'evidence': text[:2000]}
    else:
        return {'kind': 'nonzero_exit', 'exit_code': returncode,
                'evidence': text[:2000]}
    return {'kind': kind, 'signature': hashlib.sha256((kind + ':' + evidence).encode()).hexdigest(),
            'evidence': evidence}


def execute(command, cwd, env, input_path, timeout):
    captured = {}
    def drain(name, stream):
        data = bytearray(); total = 0
        while True:
            block = stream.read(8192)
            if not block:
                break
            total += len(block)
            data.extend(block[:max(0, OUTPUT_LIMIT - len(data))])
        stream.close()
        captured[name] = {'text': data.decode('utf-8', 'replace'),
                          'bytes': total, 'truncated': total > len(data)}
    def limits():
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    started = time.monotonic()
    with Path(input_path).open('rb') as inp:
        process = subprocess.Popen(command, cwd=str(cwd), env=env, stdin=inp,
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                   start_new_session=True, preexec_fn=limits)
        threads = [threading.Thread(target=drain, args=(name, stream), daemon=True)
                   for name, stream in [('stdout', process.stdout), ('stderr', process.stderr)]]
        for thread in threads:
            thread.start()
        timed_out = False
        try:
            try:
                process.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                timed_out = True
        finally:
            # Also remove descendants left behind by a completed or interrupted target.
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.wait()
            for thread in threads:
                thread.join(timeout=2)
    text = captured.get('stderr', {}).get('text', '') + '\n' + captured.get('stdout', {}).get('text', '')
    result = {'returncode': process.returncode, 'elapsed_sec': time.monotonic() - started,
              'output': captured, 'timed_out': timed_out}
    if timed_out:
        result['classification'] = {'kind': 'timeout'}
    elif len(captured) != 2 or any(v['truncated'] for v in captured.values()):
        result['classification'] = {'kind': 'output_incomplete', 'evidence': text[:2000]}
    else:
        result['classification'] = signature(text, process.returncode)
    return result


def verified_runtime(build, record):
    env = record['environment']
    target = env['TARGET_PROG']; preload = env['AFL_PRELOAD']
    for path in (target, preload):
        expected = build['runtime_sha256'].get(path)
        if not expected or not Path(path).is_file() or digest(path) != expected:
            raise RuntimeError('Replay requires the matching runtime at its original path: ' + path +
                               '. Run replay before another campaign rebuilds it.')
    return target, preload


def candidates(trial, record):
    """Map schedules to original queue bytes; raw AFL crash files lack a schedule."""
    result = []
    for relative in record.get('crash_files', []):
        rel = Path(relative)
        if len(rel.parts) != 4 or rel.parts[1] != 'scheds' or not rel.name.endswith('.sched'):
            continue
        schedule = trial / 'afl' / rel
        queue = trial / 'afl' / rel.parts[0] / 'queue'
        queue_id = rel.parts[2]
        matches = sorted(p for p in queue.glob(queue_id + '*')
                         if p.name == queue_id or p.name.startswith(queue_id + ','))
        result.append({'worker': rel.parts[0], 'schedule': schedule,
                       'input': matches[0] if len(matches) == 1 else None})
    return result


def choose(cases, maximum):
    # Round robin across workers, hash order within each worker avoids always choosing earliest IDs.
    groups = defaultdict(list)
    for case in cases:
        groups[case['worker']].append(case)
    for group in groups.values():
        group.sort(key=lambda c: hashlib.sha256(str(c['schedule'].name).encode()).hexdigest())
    ordered = []
    while any(groups.values()):
        for worker in sorted(groups):
            if groups[worker]:
                ordered.append(groups[worker].pop(0))
                if maximum and len(ordered) >= maximum:
                    return ordered
    return ordered


def replay_case(case, record, target, preload, attempts, timeout):
    result = {'worker': case['worker'], 'schedule': str(case['schedule']),
              'input': str(case['input']) if case['input'] else None, 'attempts': []}
    try:
        if case['input'] is None:
            raise ValueError('Missing or ambiguous queue input; replay skipped.')
        result['schedule_sha256'] = digest(case['schedule'])
        result['input_sha256'] = digest(case['input'])
        env = {'PATH': '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin',
               'LANG': 'C', 'LC_ALL': 'C'}
        env.update({k: str(v) for k, v in record['environment'].items() if k in REPLAY_ENV})
        env['LD_PRELOAD'] = preload
        env['LD_BIND_NOW'] = '1'
        env['SEED'] = str(record.get('worker_seeds', {}).get(case['worker'], 0))
        for _ in range(attempts):
            with tempfile.TemporaryDirectory(prefix='hive-replay-') as temp:
                cwd = Path(temp)
                shutil.copyfile(case['schedule'], cwd / 'SCHEDULE')
                shutil.copyfile(case['input'], cwd / 'input')
                env['SCHEDULE'] = './SCHEDULE'
                result['attempts'].append(execute([target], cwd, env, cwd / 'input', timeout))
    except (OSError, ValueError) as error:
        result['error'] = str(error)
    kinds = Counter(a['classification']['kind'] for a in result['attempts'])
    failures = sum(kinds[k] for k in ('assertion', 'sanitizer', 'unclassified_signal'))
    result['failure_attempts'] = failures
    result['attempt_count'] = len(result['attempts'])
    result['reproduction'] = ('incomplete' if result.get('error') or any(k in kinds for k in
        ('replay_error', 'output_incomplete', 'nonzero_exit')) else
        'all_attempts_failed' if failures == attempts else
        'intermittent_failure' if failures else 'not_reproduced')
    return result


def summarize(cases):
    signatures = {}; outcomes = Counter(); attempts = Counter()
    for case in cases:
        outcomes[case['reproduction']] += 1
        for attempt in case['attempts']:
            item = attempt['classification']; attempts[item['kind']] += 1
            if 'signature' in item:
                group = signatures.setdefault(item['signature'], {'kind': item['kind'],
                    'evidence': item['evidence'], 'attempts': 0})
                group['attempts'] += 1
    return {'byte_distinct_schedule_input_pairs': len({(c.get('schedule_sha256'), c.get('input_sha256'))
                for c in cases if c.get('schedule_sha256') and c.get('input_sha256')}),
            'case_outcomes': dict(outcomes), 'attempt_outcomes': dict(attempts),
            'diagnostic_signature_count': len(signatures), 'diagnostic_signatures': signatures,
            'distinct_bug_count': None}


def replay_campaign(manifest_path, maximum=16, attempts=3, timeout=8.0, acquire_lock=True):
    import run_hiverff as runner
    manifest_path = Path(manifest_path).resolve()
    campaign = json.loads(manifest_path.read_text())
    if maximum < 0 or attempts < 1 or timeout <= 0:
        raise ValueError('Replay limits must be nonnegative; attempts and timeout must be positive.')
    # The standard layout also works when records are mounted at a different output root.
    root = manifest_path.parents[2]
    build = json.loads((manifest_path.parent / 'build/build.json').read_text())
    report_dir = manifest_path.parent / ('replay-' + datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ') + '-' + uuid.uuid4().hex[:8])
    report_dir.mkdir()
    report_path = report_dir / 'report.json'
    report = {'schema_version': 1, 'policy': 'saved_schedule_replay_v1', 'status': 'running',
              'build_id': build['build_id'], 'settings': {'max_per_trial': maximum, 'attempts': attempts, 'timeout_sec': timeout},
              'limitations': ['Diagnostic signatures are not distinct bugs.',
                  'Saved crash schedules are capped at 100 per worker by the fuzzer; this is a sample of saved artifacts, not all crash executions.',
                  'Standalone sequential replay can differ from forkserver execution under worker contention.',
                  'Runtime hashes are verified, but system libraries and machine state are not frozen.',
                  'Supports the current launcher: no target arguments and queue bytes on stdin.'], 'trials': []}
    old_root = runner.OUT_ROOT
    runner.OUT_ROOT = root
    try:
        with runner.experiment_lock() if acquire_lock else nullcontext():
            for run in campaign['runs']:
                experiment = root / run['experiment']
                exp = json.loads((experiment / 'experiment.json').read_text())
                for entry in exp['trials']:
                    trial = experiment / Path(entry['record']).parent
                    record = json.loads((trial / 'record.json').read_text())
                    target, preload = verified_runtime(build, record)
                    cases = candidates(trial, record)
                    chosen = choose(cases, maximum)
                    row = {'replicate': run['replicate'], 'sharing': run['sharing'], 'trial': str(trial),
                           'saved_schedule_count': len(cases), 'selected_count': len(chosen),
                           'unpaired_afl_crash_files': sum('/crashes/' in p for p in record.get('crash_files', [])),
                           'cases': []}
                    report['trials'].append(row)
                    save(report_path, report)
                    for case in chosen:
                        row['cases'].append(replay_case(case, record, target, preload, attempts, timeout))
                        row['summary'] = summarize(row['cases'])
                        save(report_path, report)
                    row['summary'] = summarize(row['cases'])
                    print('Replay:', run['replicate'], run['sharing']['frequency'] + '/' + run['sharing']['novelty'],
                          row['summary']['case_outcomes'],
                          'diagnostic groups:', row['summary']['diagnostic_signature_count'], flush=True)
            report['summary'] = summarize([c for row in report['trials'] for c in row['cases']])
            modes = defaultdict(list)
            for row in report['trials']:
                modes[row['sharing']['frequency'] + '/' + row['sharing']['novelty']].extend(row['cases'])
            report['by_mode'] = {mode: summarize(cases) for mode, cases in modes.items()}
            report['status'] = ('completed_with_errors' if report['summary']['case_outcomes'].get('incomplete')
                                else 'completed')
    except KeyboardInterrupt:
        report['status'] = 'interrupted'
        raise
    except Exception as error:
        report.update(status='failed', error=str(error))
        raise
    finally:
        runner.OUT_ROOT = old_root
        save(report_path, report)
        print('Replay report:', report_path, flush=True)
    return report_path


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('ablation', type=Path)
    parser.add_argument('--max-per-trial', type=int, default=16, help='Worker-balanced sample; 0 replays all saved schedules.')
    parser.add_argument('--attempts', type=int, default=3)
    parser.add_argument('--timeout', type=float, default=8.0)
    args = parser.parse_args(argv)
    replay_campaign(args.ablation, args.max_per_trial, args.attempts, args.timeout)


if __name__ == '__main__':
    def interrupt(signum, frame):
        raise KeyboardInterrupt
    signal.signal(signal.SIGTERM, interrupt)
    main()
