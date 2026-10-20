"""Run all four feedback configurations with matched seeds and rotated order."""
import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import shlex
import signal
import uuid
import run_hiverff as runner

MODES = [('local', 'local'), ('global', 'local'), ('local', 'shared'), ('global', 'shared')]


def plan(args):
    runs = []
    for replicate in range(args.trials):
        order = MODES[replicate % 4:] + MODES[:replicate % 4]
        for frequency, novelty in order:
            runs.append((replicate + 1, [
                '--target', args.target, '--seconds', str(args.seconds),
                '--workers', str(args.workers), '--trials', '1', '--mode', 'throughput',
                '--seed-base', str(args.seed_base + replicate * args.workers),
                '--frequency', frequency, '--novelty', novelty, '--afl-sync', args.afl_sync]))
    return runs


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--target', default='/workdir/PERIOD/evaluation/CS/twostage_100/twostage_100_bad')
    parser.add_argument('--seconds', type=float, default=300)
    parser.add_argument('--workers', type=int, default=16)
    parser.add_argument('--trials', type=int, default=3, help='Replicates per configuration (four runs each).')
    parser.add_argument('--seed-base', type=int, default=100)
    parser.add_argument('--afl-sync', choices=('on', 'off'), default='on', help='Fixed across all arms; on matches September comparisons.')
    parser.add_argument('--dry-run', action='store_true')
    args = parser.parse_args(argv)
    # Use the runner's validation, including full seed range, before writing anything.
    runner.configure_cli(['--target', args.target, '--seconds', str(args.seconds),
                          '--workers', str(args.workers), '--trials', str(args.trials),
                          '--seed-base', str(args.seed_base), '--afl-sync', args.afl_sync])
    runs = plan(args)
    print(f'{len(runs)} sequential runs; {len(runs)*args.seconds/60:g} minutes of trial budgets, plus builds/startup.')
    if args.dry_run:
        for replicate, options in runs:
            command = ' '.join(shlex.quote(option) for option in options)
            print(f'Replicate {replicate}: python3 /opt/period-wip/run_hiverff.py {command}')
        return 0
    destination = runner.OUT_ROOT / 'ablations' / (datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ') + '-' + uuid.uuid4().hex[:8])
    destination.mkdir(parents=True)
    manifest = {'schema_version': 6, 'frequency_policy': runner.FREQUENCY_POLICY,
                'status': 'running', 'settings': vars(args), 'runs': []}
    record = destination / 'ablation.json'
    runner.save_json(record, manifest)
    print(f'Ablation records: {record}', flush=True)
    try:
        for replicate, options in runs:
            runner.configure_cli(options)
            experiment, result = runner.main()
            manifest['runs'].append({'replicate': replicate, 'sharing': runner.sharing_settings(),
                                     'seed_base': runner.SEED_BASE, 'status': result['status'],
                                     'experiment': str(experiment.relative_to(runner.OUT_ROOT))})
            runner.save_json(record, manifest)
            if result['status'] != 'completed':
                raise RuntimeError(f"Stopped after {experiment}: {result['status']}")
            trial = json.loads((experiment / result['trials'][0]['record']).read_text())
            if not trial['measurement_complete'] or trial.get('worker_abort_reasons') or trial.get('manager_returncode_after_stop') != 0:
                raise RuntimeError(f'Incomplete metrics or worker failure in {experiment}; inspect its record before continuing.')
        manifest['status'] = 'completed'
    except KeyboardInterrupt:
        manifest['status'] = 'interrupted'
        return 130
    except Exception as exc:
        manifest.update(status='failed', error=str(exc))
        raise
    finally:
        runner.save_json(record, manifest)
    return 0


if __name__ == '__main__':
    signal.signal(signal.SIGTERM, runner.handle_termination)
    raise SystemExit(main())
