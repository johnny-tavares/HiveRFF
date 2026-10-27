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
                '--frequency', frequency, '--novelty', novelty, '--afl-sync', args.afl_sync,
                '--all-rff', args.all_rff]))
    return runs


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--target', default='/workdir/PERIOD/evaluation/CS/twostage_100/twostage_100_bad')
    parser.add_argument('--seconds', type=float, default=300)
    parser.add_argument('--workers', type=int, default=16)
    parser.add_argument('--trials', type=int, default=4, help='Replicates per configuration (four runs each).')
    parser.add_argument('--seed-base', type=int, default=1000)
    parser.add_argument('--afl-sync', choices=('on', 'off'), default='on', help='Fixed across all arms; on matches September comparisons.')
    parser.add_argument('--all-rff', choices=('on','off'), default='on', help='Explicit runtime feedback mode; on matches the working baseline.')
    parser.add_argument('--dry-run', action='store_true')
    args = parser.parse_args(argv)
    # Use the runner's validation, including full seed range, before writing anything.
    runner.configure_cli(['--target', args.target, '--seconds', str(args.seconds),
                          '--workers', str(args.workers), '--trials', str(args.trials),
                          '--seed-base', str(args.seed_base), '--afl-sync', args.afl_sync, '--all-rff', args.all_rff])
    runs = plan(args)
    print(f'{len(runs)} sequential runs; {len(runs)*args.seconds/60:g} minutes of trial budgets, plus one build/startup.')
    if args.dry_run:
        for replicate, options in runs:
            command = ' '.join(shlex.quote(option) for option in options)
            print(f'Replicate {replicate}: python3 /opt/period-wip/run_hiverff.py {command}')
        return 0
    destination = runner.OUT_ROOT / 'ablations' / (datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ') + '-' + uuid.uuid4().hex[:8])
    destination.mkdir(parents=True)
    manifest = {'schema_version': 12, 'frequency_policy': runner.FREQUENCY_POLICY,
                'feedback_identity_policy': runner.FEEDBACK_IDENTITY_POLICY,
                'preprocessing_policy': runner.PREPROCESSING_POLICY,
                'profiling': runner.profiling_settings(),
                'status': 'setting_up', 'settings': vars(args), 'runs': [],
                'build_strategy': 'once_per_ablation', 'machine_before': runner.machine_snapshot()}
    record = destination / 'ablation.json'
    runner.save_json(record, manifest)
    print(f'Ablation records: {record}', flush=True)
    try:
        # Keep the same lock through setup and all arms; no other new runner can rebuild between them.
        with runner.experiment_lock():
            runner.preflight()
            prepared = runner.prepare_build(destination / 'build')
            manifest.update(status='running', build_id=prepared['build_id'],
                            build_manifest=prepared['manifest_path'])
            runner.save_json(record, manifest)
            for replicate, options in runs:
                runner.configure_cli(options)
                manifest['active_run'] = {'replicate':replicate, 'sharing':runner.sharing_settings(),
                                          'seed_base':runner.SEED_BASE}
                runner.save_json(record, manifest)
                experiment, result = runner.run_experiment(prepared=prepared)
                manifest['runs'].append({'replicate': replicate, 'sharing': runner.sharing_settings(),
                                         'seed_base': runner.SEED_BASE, 'status': result['status'],
                                         'build_id': result.get('build_id'),
                                         'experiment': str(experiment.relative_to(runner.OUT_ROOT))})
                runner.save_json(record, manifest)
                if result['status'] == 'interrupted':
                    raise KeyboardInterrupt
                if result['status'] != 'completed':
                    raise RuntimeError(f"Stopped after {experiment}: {result['status']}")
                trial = json.loads((experiment / result['trials'][0]['record']).read_text())
                if not trial['measurement_complete'] or trial.get('worker_abort_reasons') or trial.get('manager_returncode_after_stop') != 0:
                    raise RuntimeError(f'Incomplete metrics or worker failure in {experiment}; inspect its record before continuing.')
                workers = trial.get('workers', {})
                if len(workers) != args.workers or any(
                        (worker.get('metrics') or {}).get('schedule_bitmap_nonempty_returns', 0) <= 0
                        for worker in workers.values()):
                    raise RuntimeError(f'Missing nonempty schedule feedback from one or more workers in {experiment}; do not use this campaign for a sharing comparison. Check ALL_RFF and instrumentation.')
                manifest.pop('active_run', None)
        manifest['status'] = 'completed'
    except KeyboardInterrupt:
        manifest['status'] = 'interrupted'
        return 130
    except Exception as exc:
        manifest.update(status='failed', error=str(exc))
        raise
    finally:
        manifest['machine_after'] = runner.machine_snapshot()
        runner.save_json(record, manifest)
    return 0


if __name__ == '__main__':
    signal.signal(signal.SIGTERM, runner.handle_termination)
    raise SystemExit(main())
