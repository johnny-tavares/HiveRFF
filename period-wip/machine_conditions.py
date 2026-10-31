"""Audit sampled CPU configuration, not instantaneous speed or temperature."""


def configuration(snapshot):
    values = {}
    for policy, fields in (snapshot.get('cpufreq') or {}).items():
        for key in ('affected_cpus', 'scaling_driver', 'scaling_governor',
                    'scaling_min_freq', 'scaling_max_freq'):
            if fields.get(key) is not None:
                values['cpufreq.' + policy + '.' + key] = fields[key]
    if snapshot.get('allowed_cpus') is not None:
        values['allowed_cpus'] = snapshot['allowed_cpus']
    for key in ('cpu.max', 'cpuset.cpus.effective'):
        value = (snapshot.get('cgroup_v2') or {}).get(key)
        if value is not None:
            values['cgroup.' + key] = value
    return values


class ConfigurationAudit:
    def __init__(self):
        self.previous = None
        self.baseline = None
        self.samples = 0
        self.missing_samples = 0
        self.events = []
        self.change_count = 0
        self.invalid_samples = 0
        self.fields = set()

    def observe(self, snapshot, location):
        current = configuration(snapshot or {})
        self.samples += 1
        self.fields.update(current)
        if not current:
            self.missing_samples += 1
        if self.previous is not None:
            for key in sorted(set(self.previous) | set(current)):
                old, new = self.previous.get(key), current.get(key)
                if old != new:
                    self.change_count += 1
                    if len(self.events) < 100:
                        self.events.append({'location': location, 'field': key,
                                            'before': old, 'after': new})
        else:
            self.baseline = current
        self.previous = current

    def result(self):
        status = ('changed' if self.change_count else
                  'incomplete' if self.invalid_samples else
                  'unavailable' if not self.fields else
                  'insufficient_samples' if self.samples < 2 else 'stable_observed')
        return {'policy': 'sampled_cpu_configuration_v1', 'status': status,
                'timing_configuration_consistent': False if self.change_count else
                    True if status == 'stable_observed' else None,
                'samples': self.samples, 'missing_samples': self.missing_samples,
                'invalid_samples': self.invalid_samples,
                'fields_observed': sorted(self.fields), 'baseline': self.baseline,
                'change_count': self.change_count, 'changes': self.events,
                'changes_truncated': self.change_count > len(self.events),
                'limitation': 'Sampled configuration only. Unobserved changes, thermal throttling, '
                              'background load and power-source changes are not ruled out.'}


def observe_trial(audit, directory, record):
    import json
    audit.observe(record.get('machine_before'), str(directory) + ':before')
    timeline = directory / 'timeline.jsonl'
    if timeline.exists():
        with timeline.open() as stream:
            for line in stream:
                try:
                    row = json.loads(line)
                except (ValueError, TypeError):
                    audit.invalid_samples += 1
                    continue
                if not isinstance(row, dict):
                    audit.invalid_samples += 1
                    continue
                audit.observe(row.get('machine'), str(directory) + ':' + str(row.get('elapsed_sec')))
    audit.observe(record.get('machine_after'), str(directory) + ':after')
