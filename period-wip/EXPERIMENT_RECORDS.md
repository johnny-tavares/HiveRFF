# Experiment records

Run inside the existing container as before:

```sh
python3 /opt/period-wip/run_hiverff.py
```

The runner recompiles the mounted manager, AFL C code, and mutator automatically, including hive_metrics.h. No Docker image rebuild is needed. See MEASUREMENT_SEMANTICS.md for schema 6 definitions and coordination counters.

Each invocation creates `/opt/out/experiments/<UTC timestamp>-<unique suffix>/` (the host's mounted `out/experiments/`):

- `experiment.json`: configuration, planned trials, source/runtime SHA-256 hashes, lifecycle status, and trial record links.
- `setup.log`: build and instrumentation output.
- `trial-001/record.json`: settings, worker seeds, outcome, monotonic elapsed time, first crash observation, final worker statistics, and crash artifact paths.
- `trial-001/console.log`: manager and worker stdout/stderr.
- `trial-001/afl/worker_*/`: original AFL files, including queues, schedules, crash artifacts, fuzzer_stats, and plot_data where emitted.

Existing `out/worker_*` folders are preserved. No shared-memory-wide deletion or global process-name kill is performed. One runner at a time per container is required because worker scratch paths remain global. The output-root lock prevents simultaneous new runners sharing that output mount; do not run the old runner or a second runner with a different mount concurrently.

Both SPEED and THROUGHPUT honor --trials (default 5); the manifest records the planned count. No success-only averages are produced. Outcomes include crash_found, timeout, budget_completed, failed, and interrupted. A running record after abrupt container termination indicates an unfinished run, not success. Missing counters are null, not zero.

The clock starts immediately before manager launch and includes worker startup. Crash timing is the first polling observation (50 ms polling interval plus scanning/scheduling overhead), not an exact crash timestamp. Final counters can include work completed during shutdown and are periodically published by AFL; they are not exact schedules-to-first-crash. Crash files are neither deduplicated nor independently validated bugs. Missing worker statistics flag a failed run, but this is not yet continuous worker health monitoring.

Mode-specific settings are preserved, including MASK=0x3FFF for THROUGHPUT. Effective AFL-prefixed and selected scheduling environment variables are recorded; unrelated environment variables are not dumped. Source hashes identify file content; runtime hashes are taken after setup. A missing file fingerprint is null.

Ctrl+C and SIGTERM save interrupted status and stop the trial's process group. SIGKILL/power loss cannot finalize records; original per-trial output remains in place. Setup failures are saved at experiment level.

Run the lightweight record tests without Docker or actual fuzzing:

```sh
python3 /opt/period-wip/test_records.py
```

Schema 2 adds worker hive_metrics.json, bounded energy_decisions.jsonl, and per-trial timeline.jsonl. The old total_schedules field is replaced by explicitly named mutation and execution counters. Check measurement_complete and per-worker final markers.

## Sharing controls (schema 5)

Defaults: CS/twostage_20/twostage_20_bad, 16 workers, 120 seconds per trial,
throughput mode, five trials, global frequency, shared novelty, AFL queue synchronization off.
Setup/build time is outside the trial budget. Each configuration takes about ten minutes
plus setup and shutdown. Throughput retains first-crash timing while continuing exploration.
Queue sync stays off across the comparisons below to isolate feedback sharing.
The existing mounted container can stay open: the runner rebuilds the changed components.

```sh
# Shared frequency and novelty
python3 /opt/period-wip/run_hiverff.py --frequency global --novelty shared --afl-sync off
# Matched frequency ablation (keep novelty and queue synchronization identical)
python3 /opt/period-wip/run_hiverff.py --frequency local --novelty shared --afl-sync off
# Independent worker information
python3 /opt/period-wip/run_hiverff.py --frequency local --novelty local --afl-sync off
# Optional fourth combination
python3 /opt/period-wip/run_hiverff.py --frequency global --novelty local --afl-sync off
```

All commands use five 120-second trials and 16 workers unless overridden with
--trials, --seconds, and --workers. Select another benchmark with its absolute executable
path, for example `--target /workdir/PERIOD/evaluation/CS/twostage_100/twostage_100_bad`.
For a short integration check, add --trials 1 --seconds 60.
The target executable and mempair.twostage_20_bad must exist under
/workdir/PERIOD/evaluation/CS/twostage_20 in the container.
Run sequentially. Use --trials N to repeat either mode. Worker seeds are
`seed_base + (trial_number - 1) * workers + worker_index + 1`; default seed base is 100.
Use the same --seed-base across paired arms and change it across independent replicates.
These are mutator seeds; concurrent timing and AFL's own randomness are not deterministic.

The runner sets HIVE_FREQUENCY_MODE, HIVE_NOVELTY_MODE, HIVE_AFL_SYNC, and HIVE_SEED_BASE
explicitly. It also records AFL_SKIP_CPUFREQ=1 so host governor changes do not abort workers.
The manager validates the sharing controls. Local frequency uses the existing Zig hash table;
local novelty uses a private AFL virgin map. With queue sync off, AFL uses -d instead of -S
and writes directly to its worker directory, retaining the same record layout. Both modes
skip deterministic input mutations so workers reach schedule fuzzing promptly: -S implies
-d, while independent workers need it explicitly. AFL rejects combining -S with -d. The manager reuses the legacy named shared-memory segment, resets it before launch,
and unlinks it after normal shutdown. This avoids a second 50 MB allocation when an
already-open container still has the old segment. One manager at a time is required. Shared novelty is initialized once by the
manager, preventing late workers from resetting discoveries. Shared novelty updates retain
the existing non-atomic implementation; this change does not solve simultaneous update races.

experiment.json and trial records include sharing settings and seeds. Worker metrics report
actual frequency_mode, novelty_mode, and afl_sync. Decision events use selected_frequency_count
plus frequency_mode instead of the old global_bucket_count name, which was misleading for local mode.
The cutoff uses matching observation totals and distinct-count populations in each mode. See MEASUREMENT_SEMANTICS.md for the changed energy rule.

`target_inputs/` preserves available target .c source, mempair input, and generated out.csv.
Their hashes and the PERIOD Git commit are recorded under target_provenance. Missing files/revision
are null. This records provenance; it does not pin future Docker builds or establish a clean Git tree.

Local validation:
```sh
python3 /opt/period-wip/test_records.py
python3 /opt/period-wip/test_sharing.py
```
The sharing tests compile against the existing AFL headers and libmutator.a and exercise
cross-process frequency/novelty visibility, startup map preservation, scoring, JSON metrics,
and all eight launcher combinations. Launcher wrappers suppress filesystem setup and AFL execution.
A real benchmark run is still required for end-to-end confirmation.

## After the normalization fix (schema 6)

First run a short four-configuration integration check inside the existing container:

```sh
AFL_SKIP_CPUFREQ=1 python3 /opt/period-wip/run_ablation.py --seconds 30 --trials 1
```

This selects twostage_100_bad explicitly, 16 workers, and AFL sync on, matching the September
comparison target and sync setting. Four trial budgets total two minutes, plus compilation
and startup. It stops if a run fails, misses final worker metrics, records worker aborts,
or exits the manager unsuccessfully. No Docker image rebuild is needed.

Then run the matched comparison:

```sh
AFL_SKIP_CPUFREQ=1 python3 /opt/period-wip/run_ablation.py --seconds 300 --trials 3
```

This runs local/local, global/local, local/shared and global/shared for each of three seed
sets, rotating configuration order between seed sets. Every replicate uses matching worker
seeds in all four arms. All arms use --afl-sync on; override it once to off if evaluating fully
independent workers, keeping it fixed across the entire comparison. The trial budgets total
60 minutes, plus builds/startup. Use --dry-run to inspect commands without launching anything.
Rotation reduces a fixed order bias but does not control machine load or make runs deterministic.

Individual records remain under out/experiments. A controller manifest at
out/ablations/<timestamp-id>/ablation.json links the runs to configurations and replicates.
Every individual experiment has trial-001 because each invocation runs one replicate of one
configuration; use the controller manifest's replicate field for pairing.

Both local and shared scheduling changed. Recollect all four arms with schema 6 and
frequency_policy=population_mean_v1; do not compare only new shared results to old local results.

Additional controller tests:
```sh
python3 /opt/period-wip/test_ablation.py
```
