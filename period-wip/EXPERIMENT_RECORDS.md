# Experiment records

Run inside the existing container as before:

```sh
python3 /opt/period-wip/run_hiverff.py
```

The standalone runner recompiles the mounted manager, AFL C code, mutator, and scheduling runtime automatically, including hive_metrics.h and libsched.cpp. The ablation controller described below builds once and reuses that build for every arm. No Docker image rebuild is needed. See MEASUREMENT_SEMANTICS.md for runner schema 12, worker schema 11, and coordination counter definitions.

Each invocation creates `/opt/out/experiments/<UTC timestamp>-<unique suffix>/` (the host's mounted `out/experiments/`):

- `experiment.json`: configuration, planned trials, source/runtime SHA-256 hashes, lifecycle status, and trial record links.
- `setup.log`: build and instrumentation output.
- `trial-001/record.json`: settings, worker seeds, outcome, monotonic elapsed time, first crash observation, final worker statistics, and crash artifact paths.
- `trial-001/console.log`: manager and worker stdout/stderr.
- `trial-001/afl/worker_*/`: original AFL files, including queues, schedules, crash artifacts, fuzzer_stats, and plot_data where emitted.

Existing `out/worker_*` folders are preserved. No shared-memory-wide deletion or global process-name kill is performed. One runner at a time per container is required because worker scratch paths remain global. The output-root lock prevents simultaneous new runners sharing that output mount; do not run the old runner or a second runner with a different mount concurrently.

Both SPEED and THROUGHPUT honor --trials (default 5); the manifest records the planned count. No success-only averages are produced. Outcomes include crash_found, timeout, budget_completed, failed, and interrupted. A running record after abrupt container termination indicates an unfinished run, not success. Missing counters are null, not zero. Machine observations are also stored at trial start, finish, and each timeline sample; see the machine-observations section below.

The clock starts immediately before manager launch and includes worker startup. Crash timing is the first polling observation (50 ms polling interval plus scanning/scheduling overhead), not an exact crash timestamp. Final counters can include work completed during shutdown and are periodically published by AFL; they are not exact schedules-to-first-crash. Crash files are neither deduplicated nor independently validated bugs. Missing worker statistics flag a failed run, but this is not yet continuous worker health monitoring.

Mode-specific settings are preserved, including MASK=0x3FFF for THROUGHPUT. Effective AFL-prefixed and selected scheduling environment variables are recorded; unrelated environment variables are not dumped. Source hashes identify file content; runtime hashes are taken after setup. A missing file fingerprint is null.

Ctrl+C and SIGTERM save interrupted status and stop the trial's process group. SIGKILL/power loss cannot finalize records; original per-trial output remains in place. Setup failures are saved at experiment level.

Run the lightweight record tests without Docker or actual fuzzing:

```sh
python3 /opt/period-wip/test_records.py
```

Schema 2 adds worker hive_metrics.json, bounded energy_decisions.jsonl, and per-trial timeline.jsonl. The old total_schedules field is replaced by explicitly named mutation and execution counters. Check measurement_complete and per-worker final markers.

## Sharing controls

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
The reference mean uses matching observation totals and distinct-count populations in each
mode. Traces at or below that mean keep their candidate energy. Hotter traces receive an
blend of three parts full energy and one part `mean/count` proportional score, retaining at least 75% of
their candidate. See MEASUREMENT_SEMANTICS.md for the exact rule and counters.

`target_inputs/` preserves available target .c source, mempair input, and generated out.csv.
Their hashes and the PERIOD Git commit are recorded under target_provenance. Missing files/revision
are null. This records provenance; it does not pin future Docker builds or establish a clean Git tree.

Local validation:
```sh
python3 /opt/period-wip/test_records.py
python3 /opt/period-wip/test_sharing.py
```
The sharing tests compile against the existing AFL headers, build the mounted `mutator.zig`
into a temporary library, and exercise cross-process frequency/novelty visibility, startup
map preservation, scoring, JSON metrics, and all eight launcher combinations. An explicit
`HIVE_LIBMUTATOR` remains available for host-only testing. Launcher wrappers suppress
filesystem setup and AFL execution.
A real benchmark run is still required for end-to-end confirmation.

## Controlled comparison (runner schema 12, worker schema 11)

### Stable cross-worker feedback identities

The runner records `feedback_identity_policy=module_relative_stack_v2`. Mutex event
contexts hash each stack frame as its module name plus its offset from that module's load
base. This gives equivalent call paths the same identity in independently randomized worker
processes while retaining distinct call paths. The earlier absolute-address scheme was
stable only inside one process: ASLR changed shared-library addresses between workers, so
equivalent events could receive unrelated schedule bitmap and trace identities.

The mounted libsched.cpp is now copied into `/opt/sched-fuzz` before instrumentation builds
libsched.so. Its source and compiled runtime fingerprints are included in the shared build
guard. Keep ASLR enabled; disabling it would hide the identity defect rather than test the
portable representation. `test_sharing.py` builds the runtime and verifies identity equality
across eight fresh processes, within-process stability, and separation of two call sites.

Results produced before this policy are useful evidence about the old implementation, but
they do not measure properly keyed cross-worker frequency sharing. Run a new integration
check before drawing performance conclusions from the fix.

First run a short four-configuration integration check inside the existing container:

```sh
python3 /opt/period-wip/run_ablation.py --seconds 30 --trials 1 --seed-base 1000
```

This selects twostage_100_bad, 16 workers, AFL sync on, and ALL_RFF=1 explicitly.
The controller defaults to --all-rff on, overriding an absent or zero shell setting.
AFL_SKIP_CPUFREQ=1 is already set by the runner. Four trial budgets total two minutes,
plus one build, startup and shutdown. No Docker image rebuild is needed.
The standalone run_hiverff.py retains --all-rff inherit for compatibility; use
--all-rff on there to select the same runtime feedback mode.

The controller checks for a piped host core_pattern and NO_RFF before building. It does
not change either setting. During the campaign it stops on failed trials, missing final
worker metrics, worker aborts, a bad manager exit, or any worker lacking nonempty schedule
feedback. A failed campaign retains its records for diagnosis; do not treat it as a completed
sharing comparison. --all-rff off is available for intentional selective-feedback experiments,
but the same nonempty-feedback requirement applies.

After the integration check succeeds, run the matched comparison on an otherwise idle machine:

```sh
python3 /opt/period-wip/run_ablation.py --seconds 300 --trials 4 --seed-base 1000
```

This runs local/local, global/local, local/shared and global/shared for each of four fresh
seed sets. The default seed base is now 1000. Every replicate uses matching worker seeds
in all four arms. With four replicates, rotating configuration order places each arm in
each run position once. All arms use --afl-sync on; override it once to off if evaluating
independent workers, keeping it fixed across the entire comparison. The trial budgets total
80 minutes, plus one build and startup/shutdown. Four replicates improve order balance;
they do not by themselves establish a statistically reliable performance advantage.

Use --dry-run to preview each arm's equivalent standalone settings without writing files
or launching anything. Running those printed commands individually rebuilds each invocation;
use run_ablation.py for the shared-build campaign.

### One build for the whole campaign

The controller holds the output-root lock throughout setup and all arms. It saves build
logs, copies of the runtime artifacts, target inputs, fingerprints, and a build ID under
out/ablations/<timestamp-id>/build/. Every experiment points to this same build manifest.
Before and after trials, it verifies runtime/source/target-input fingerprints and the seed
corpus inventory. Unexpected changes stop the comparison. Setup runs once; AFL C, the
mutator, and manager remain on frequency_policy=guarded_frequency_energy_v4 for the
whole campaign.

Individual records remain under out/experiments. The controller's ablation.json links the
runs to configurations and replicates. Every individual experiment has trial-001 because
each experiment runs one replicate of one configuration; use the controller manifest's
replicate field for pairing. Each experiment's setup.log points to the shared build log.

### Machine observations

Trial record.json contains machine_before and machine_after. Each timeline.jsonl sample
also includes machine. These read aggregate load averages, CPU tick counters, selected
memory counters, CPU affinity, reported CPU frequency/governor data, and visible cgroup-v2
CPU limits/usage/throttling when accessible. Unavailable fields are null. Collection time
is recorded, and the reads introduce some overhead. No host settings are changed.

These are container-visible observations: load and CPU ticks may cover the whole host,
CPU frequency values depend on the driver's reporting, and some cgroup files may be
unavailable. They help identify possible interference but cannot prove why execution time
changed. When deriving CPU utilization from deltas, guest and guest_nice are already
included in user and nice; do not count them twice. Consult the
[Linux CPU frequency documentation](https://docs.kernel.org/admin-guide/pm/cpufreq.html)
and [cgroup v2 documentation](https://docs.kernel.org/admin-guide/cgroup-v2.html).

The blended policy changes both local and shared scheduling. Use all four arms with worker
schema 9 and frequency_policy=guarded_frequency_energy_v4. Worker schemas 6, 7 and 8 remain
evidence about earlier policies and are not direct performance comparisons.
Crash artifacts still require replay/validation before any claim about distinct bugs.

Local harness tests (no real fuzzing):
```sh
python3 /opt/period-wip/test_records.py
python3 /opt/period-wip/test_ablation.py
```


## Opt-in profiling (runner schema 12, worker schema 11)

The scheduling policy remains guarded_frequency_energy_v4. Set `HIVE_PROFILE=1`
for phase_timing_schedule_fingerprints_v1 diagnostics; unset it or use 0 for regular
runs. Other values fail validation. Workers publish the actual enabled state, and
runner records/builds/ablation manifests retain the requested profiling settings.

```sh
python3 /opt/period-wip/test_sharing.py &&
HIVE_PROFILE=1 ALL_RFF=1 AFL_SKIP_CPUFREQ=1 python3 /opt/period-wip/run_ablation.py \
  --seconds 60 --trials 1 --seed-base 10000
# Use the ablation.json path printed by that run:
python3 /opt/period-wip/analyze_profile.py /opt/out/ablations/<run>/ablation.json
```

Each worker's profile.jsonl logs parent scoring decisions and schedule execution
outcomes, up to 100,000 combined rows. The cap does not stop timing counters.
`profile_dropped_rows`, missing files, malformed records, and missing final metrics
cause the analyzer to mark its overlap report incomplete. Capped overlap covers a
prefix; it is not an estimate of full-run uniqueness. --json retains per-worker
counts and selection concentration. The report can also accept trial record.json.

Timing counters measure calls and monotonic nanoseconds for parent scoring,
mutation generation, writing SCHEDULE, run_target (including interrupted calls),
novelty checks, frequency-table updates, local diagnostic-table updates, and new
profiling work. `target_parent_cpu` uses the fuzzer thread's CPU clock during
run_target; it excludes CPU consumed by the target child and is nested inside
`target_wall`. Low parent CPU with high target wall time does not distinguish child
computation, instrumentation, OS scheduling, synchronization, or I/O. Selection
includes existing telemetry publication, so profile flushing can overlap selection.
These phases do not partition whole-run time: startup, replay, saving discoveries,
AFL work, and uninstrumented paths remain outside them. Do not sum all timers into
a wall-time total. All aggregated durations are worker time, not swarm elapsed time.

Schedule fingerprints are 64-bit FNV-1a hashes of explicit little-endian fields:
seed, delay, distribution, avoid-uninitialized-writes flag, positive/negative
obligation lengths, and ordered read/write event IDs. Pointers and struct padding
are excluded. shape_hash omits only the seed. Input content is fingerprinted too;
overlap compares (input hash, schedule/shape/trace hash) within a single build.
Parent hashes identify selected parent specifications. These are hash-based
identities with possible collisions; they are not captured concrete interleavings.
Event-ID comparability still depends on the existing instrumentation identity
assumptions. Hashes across different builds must not be treated as equivalent.

The analyzer reports the union and sum of worker-local distinct identities.
Their difference measures redundant worker memberships, not execution time saved.
Interrupted executions are excluded from overlap. Full schedule and shape overlap
answer different questions; identical shape with different seeds is not an exact
repeat of the schedule specification.

Profiling adds clock reads, hashing, and buffered file I/O, and may perturb thread
scheduling. The diagnostics timer captures new hashing/logging/flush work but does
not account for all timing-probe overhead. Treat this as a diagnostic campaign,
not direct proof of a throughput improvement over unprofiled runs.


## Checked preprocessing (runner schema 12, worker schema 11)

`preprocessing_policy=checked_worker_local_pairs_v1` fixes a missing relative
all_event_pairs.py invocation that previously left workers without RF constraints.
The runner checks Python, Java, the trace-conversion script, pair-generation script,
and predictor JAR before building. Tool sources and predictor library JARs join the
build fingerprints. all_event_pairs.py is now included in the mounted period-wip
folder, independent of whether the Docker image contains that script.

The fuzzer calls tools with argv arrays (no shell), using absolute script/JAR paths.
It unsets LD_PRELOAD only in the subprocess. Logs and pair outputs are generated in
each worker directory. The launcher links only immutable out.csv and seed input;
it no longer links mutable log/pair files. Old outputs are removed before replay;
missing files during cleanup are allowed, other removal failures abort. A replay
fault, command nonzero exit/signal, missing tool, or invalid/missing pair file aborts
the worker and records a preprocessing failure. The manager stops remaining workers
when a worker fails. Runner status becomes failed for worker aborts or manager errors.

The Zig loader returns separate status and counts. It validates JSON, matching
relation/score lengths, and finite scores in [0,1] before modifying cumulative state.
Valid empty data is allowed and explicitly reported. A missing or malformed file is
never interpreted as an empty dataset. The compatibility read_rf_set function also
aborts on load failure. Out-of-memory failures remain fatal.

Worker metrics include preprocess_runs, preprocess_failures, pair_loads,
pair_empty_loads, pair_last_count, and pair_available. The last two describe file
records and cumulative worker-local unique pairs; do not sum them as global distinct
pairs. `preprocessing_complete` requires each modern worker to complete a successful
load without a failure. A valid empty load meets that condition; it does not prove
constraint-guided exploration. Check pair_available and mutation_obligation_changes
before interpreting an ablation as exercising structural mutations.

Mutation counters compare generated specifications against their immediate parent:
mutation_obligation_changes, mutation_seed_changes, mutation_flag_changes,
mutation_unchanged, mutation_initial_schedules, mutation_with_obligations.
Changes can overlap (e.g. both seed and constraints change); these are output changes,
not attempted operator counts or observed execution coverage. They are collected even
with HIVE_PROFILE=0. V4 scoring is unchanged.

Validation: test_sharing.py builds the mounted Zig mutator and runs test_preprocess.py
alongside existing identity/scoring/sharing/launcher checks. The new suite exercises
real pair generation with fixture conversion/prediction tools, successful/empty loads,
missing/malformed/mismatched/invalid-score data, no partial update on invalid data,
structural mutation generation, command failure/signals, missing executables/tools,
and isolated worker outputs. Full Java/target replay still requires the Docker smoke run.
