"""Read optional Hive profiles. Usage: analyze_profile.py ABLATION_JSON [--json]."""
import argparse
from collections import Counter
import json
from pathlib import Path

PHASES = ('selection', 'mutation', 'schedule_write', 'target_wall',
          'target_parent_cpu', 'novelty', 'frequency_update', 'local_observe', 'diagnostics')

def overlap(sets):
    union = set().union(*sets) if sets else set()
    summed = sum(map(len, sets))
    return {'union': len(union), 'sum_worker_unique': summed,
            'redundant_worker_memberships': summed-len(union),
            'redundant_worker_fraction': (summed-len(union))/summed if summed else None}

def analyze_trial(path):
    path = Path(path)
    record = json.loads(path.read_text())
    all_sets = {name: [] for name in ('schedule', 'shape', 'trace', 'parent')}
    warnings = []
    phase_ns = {name: 0 for name in PHASES}
    phase_calls = {name: 0 for name in PHASES}
    worker_details = {}
    usable = 0
    for worker, entry in record['workers'].items():
        metrics = entry.get('metrics') or {}
        file = path.parent/'afl'/worker/'profile.jsonl'
        if not metrics.get('profiling_enabled'):
            warnings.append(worker + ': profiling disabled or unavailable')
            continue
        for name in PHASES:
            phase_ns[name] += metrics.get('profile_'+name+'_ns', 0)
            phase_calls[name] += metrics.get('profile_'+name+'_calls', 0)
        # Timing counters live in record.json and remain usable without raw logs.
        # is_file() can hide permission errors as False on newer Python versions.
        try:
            stream = file.open()
        except FileNotFoundError:
            warnings.append(worker + ': missing profile.jsonl')
            continue
        except OSError as error:
            warnings.append(worker + ': cannot read profile.jsonl: ' + str(error))
            continue
        usable += 1
        sets = {name: set() for name in all_sets}
        parents = Counter()
        rows = executions = selections = malformed = 0
        with stream:
            for line in stream:
                try:
                    e = json.loads(line)
                    if e['schema_version'] != 1 or e['kind'] not in ('selection','execution'):
                        raise ValueError('unsupported profile row')
                    inp = e['input_hash']
                    if e['kind']=='selection':
                        if e['parent_present']:
                            key=(inp,e['parent_hash'])
                            sets['parent'].add(key); parents[key] += 1
                        selections += 1
                    elif not e['interrupted']:
                        sets['schedule'].add((inp,e['schedule_hash']))
                        sets['shape'].add((inp,e['shape_hash']))
                        sets['trace'].add((inp,e['outcome_trace']))
                        executions += 1
                    rows += 1
                except (ValueError, KeyError, TypeError):
                    malformed += 1
        dropped = metrics.get('profile_dropped_rows', 0)
        if dropped: warnings.append(worker + ': capped log; overlap covers only a prefix')
        if malformed: warnings.append(worker + ': malformed rows: ' + str(malformed))
        if rows != metrics.get('profile_rows'):
            warnings.append(worker + ': row count differs from final metrics')
        expected = metrics.get('profile_selection_calls',0)+metrics.get('profile_target_wall_calls',0)
        if rows+dropped != expected:
            warnings.append(worker + ': profile rows do not cover all measured calls')
        if not metrics.get('final'): warnings.append(worker + ': metrics are not final')
        for name in sets: all_sets[name].append(sets[name])
        worker_details[worker] = {
            'logged_completed_executions': executions, 'logged_selections': selections,
            'unique_schedules': len(sets['schedule']),
            'within_worker_repeated_specs': executions-len(sets['schedule']),
            'unique_selected_parents': len(sets['parent']),
            'top_parent_selection_fraction': max(parents.values())/sum(parents.values()) if parents else None}
    if not record.get('measurement_complete'): warnings.append('trial measurements incomplete')
    return {'trial': str(path), 'sharing': record['sharing'],
            'frequency_policy': record.get('frequency_policy'),
            'workers_with_profiles': usable, 'expected_workers': len(record['workers']),
            'completed_executions': record['totals'].get('schedule_executions_completed'),
            'phase_worker_seconds': {name: phase_ns[name]/1e9 for name in PHASES},
            'phase_mean_us': {name: phase_ns[name]/phase_calls[name]/1000 if phase_calls[name] else None for name in PHASES},
            'overlap': {name: overlap(sets) for name,sets in all_sets.items()},
            'workers': worker_details, 'warnings': warnings}

def analyze(path):
    path = Path(path)
    data = json.loads(path.read_text())
    if 'runs' not in data:
        return [analyze_trial(path)]
    # Manifests store experiments relative to the output root; works on host and in Docker.
    root = path.parent.parent.parent
    reports=[]
    for run in data['runs']:
        report=analyze_trial(root/run['experiment']/'trial-001/record.json')
        report['replicate']=run['replicate']; reports.append(report)
    return reports

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('record',type=Path)
    parser.add_argument('--json',action='store_true')
    args=parser.parse_args(); reports=analyze(args.record)
    if args.json:
        print(json.dumps(reports,indent=2)); return
    print('Phase times are summed worker seconds; parent CPU is part of target wall time.')
    print('Selection includes publication; diagnostics flush time can overlap selection.')
    print('Overlap is hash-based and within this build. Shape excludes the schedule seed.')
    for r in reports:
        s=r['sharing']; print('\nreplicate',r.get('replicate','-'),s['frequency']+'/'+s['novelty'],r['completed_executions'],'completed')
        print('  profiles:',r['workers_with_profiles'],'/',r['expected_workers'])
        print('  worker seconds:', ', '.join(k+'='+format(v,'.4f') for k,v in r['phase_worker_seconds'].items()))
        print('  mean microseconds:', ', '.join(k+'='+format(v,'.2f') for k,v in r['phase_mean_us'].items() if v is not None))
        parent_counts=[w['unique_selected_parents'] for w in r['workers'].values()]
        print('  unique selected parents per worker:',parent_counts)
        for name,o in r['overlap'].items():
            print(' ',name,'union:',o['union'],'sum worker unique:',o['sum_worker_unique'])
        for warning in r['warnings']: print('  INCOMPLETE:',warning)

if __name__=='__main__': main()
