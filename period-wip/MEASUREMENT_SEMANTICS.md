# Measurement semantics (runner schema 12, worker schema 11)

The standalone runner copies and rebuilds `afl-fuzz.c`, `mutator.zig`, `hive_metrics.h`, and `libsched.cpp` from period-wip, then compiles hivemind.c. No Docker image rebuild is required. Use the same mounted-file runner command as before. The ablation controller builds once for all arms, archives the artifacts, and checks fingerprints before and after trials. See EXPERIMENT_RECORDS.md for the controlled comparison commands.

## Files

Each worker writes atomic `hive_metrics.json` snapshots roughly once per second while making energy decisions or returning from schedule executions, plus a final snapshot on orderly shutdown. Long executions can delay publication. Each worker saves the first 1000 scored parents and every 1000th scored parent thereafter in `energy_decisions.jsonl`. This is a systematic diagnostic sample, not a random or representative sample. Summary counters cover every decision.

The runner writes `timeline.jsonl` once per second with the latest published worker snapshots, and retains each snapshot's age. Trial `record.json` has separate `at_stop_request` and final snapshots; grace-period activity can appear only in the latter. `measurement_complete` requires all worker metrics to have final=true. `budget_completed` alone does not certify complete telemetry or prove all workers stayed healthy throughout.

## Runner schema 10

Worker schema 9 introduces guarded_frequency_energy_v4. It retains the energy-assignment
counters from schemas 7 and 8 but limits frequency suppression to 25% of candidate energy. Runner
schema 10 records that policy in builds, trials and ablations. The machine observations
introduced in runner schema 7 remain present.
Container-visible host load, CPU ticks, memory, allowed CPUs, frequency reports and cgroup-v2
counters are observations, not controlled experimental inputs. The collector records its
duration and adds read overhead. Frequency snapshots need not be exact hardware execution
frequencies. CPU tick guest fields overlap user/nice fields.

The controller defaults to ALL_RFF=1 explicitly and rejects trials with missing nonempty
schedule feedback. Its four-replicate default balances arm positions and pairs seeds.
This does not eliminate scheduler nondeterminism or establish bug-finding superiority.

## What is counted

- `mutations_generated`: returned calls to sched_mutate in the schedule fuzzing loop.
- `schedule_executions_started`: calls to run_target from sched_fuzz_stuff.
- `schedule_executions_completed`: those calls that returned with no shutdown requested, partitioned into normal, crash, timeout, and other error returns. Does not include calibration, preprocessing replays, or other AFL executions.
- `schedule_executions_interrupted`: those calls that returned while shutdown was requested. A worker killed before returning may retain a started/completed mismatch and final=false.
- `completed_execution_wall_ns`: monotonic duration of completed calls summed within the worker. Summing across workers is aggregate worker time, not swarm elapsed time or CPU time.
- `code_novelty_returns` and `rf_only_novelty_returns`: successful executions returning the corresponding existing novelty classification. These are discovery events, not numbers of distinct RF relations. RF-only follows the existing rule that checks schedule novelty only when code novelty was not found.
- `worker_unique_{completed,normal,crash,timeout,error}_trace_hashes`: distinct schedule-map hashes observed by each worker for completed schedule executions, split by outcome. Trial totals sum worker-local cardinalities, so the same hash can contribute once per worker. These hashes reveal outcome diversity but remain hash identities rather than exact concrete schedules.
- `schedule_bitmap_empty_returns` and `schedule_bitmap_nonempty_returns`: completed executions classified by whether the schedule-map hash equals the known all-zero bitmap hash. Each worker also reports `empty_schedule_bitmap_hash` and `first_completed_trace_hash` for direct diagnosis. A 32-bit hash collision is theoretically possible.
- `legacy_mutations_generated`: the sum of old num_scheds.txt files. This counter increments inside Zig mutation generation before execution; it must not be called schedules executed or unique schedules.
- Crash artifact counts are not unique bugs; crash_returns are execution outcomes, not replay-validated vulnerabilities.

## Frequency policy: guarded_frequency_energy_v4

### Feedback identity: module_relative_stack_v2

Mutex event contexts use a hash of ordered stack frames. Each frame is represented by the
loaded module name and its code offset from that module's base. Absolute process addresses
are excluded. This makes the identity comparable across AFL workers when ASLR relocates
libsched or another shared object. Unresolved frames contribute only a fixed marker and
their stack position; they never fall back to a randomized raw address. The stack buffer is
automatic storage, removing the allocation leak in the previous helper.

Instrumented memory events already receive their event ID from the instrumentation address.
The current target and instrumented target are fixed-address executables; the module-relative
change fixes mutex lock, trylock, and unlock contexts generated inside libsched. If future
targets are PIE, their instrumented event IDs must receive the same cross-process stability
test before comparison.

The regression compiles the mounted libsched.cpp and calls the context function from two
fixed call paths in eight fresh processes. It requires one stable identity per call path
across all processes, repeated-call stability, and different identities for the two paths.
This establishes identity behavior directly; benchmark ablations are still required to
measure whether sharing improves exploration or bug discovery.

Worker schema 9 changes scheduling in BOTH local and global frequency modes. Rerun the
local baseline; worker schemas 6, 7 and 8 measure earlier policies.

The reference frequency is `floor(selected normal schedule observations / selected distinct
traces)`, with a minimum of one. Local mode uses the worker's normal observations and distinct
trace hashes; global mode uses atomic swarm normal observations and occupied frequency buckets.
The numerator now counts exactly the same `store_path_id` calls as the frequencies. It excludes
calibration, replay, crash, timeout, error and interrupted executions. The old numerator used
all worker-local AFL executions, even with global frequencies and distinct trace counts.

Candidate batch energy remains on the worker-local scale in both modes:
`min(stage_max, floor(2^next_fuzz_level / local_mean) * base_score)`. A trace at or below
the selected mean keeps that candidate. A hotter trace receives
`ceil(candidate * (3 + selected_mean / selected_count) / 4)`: three parts full energy
and one part proportional energy. This retains at least 75% of the candidate. It reduces
the penalty on common parents; improved throughput or crash discovery requires measurement.
There is no rejection loop or adaptive cutoff adjustment. Multiplying the number of
otherwise identical workers multiplies the global count and mean equally, so the weight is
invariant to worker count. A 128-bit intermediate prevents overflow.

The observational local table now supplies the local energy denominator and local-policy
diagnostic. It is updated at the same normal-execution point as the Zig table/scoreboard.
This adds measurement cost in every mode; the new atomic global total also adds shared-mode cost.

### Counters and decision events

- `local_frequency_observations`: normal observations added by this worker. Summable.
- `selected_frequency_observations`, `selected_frequency_trace_buckets`: current local or
  global population snapshots, interpreted using `frequency_mode`. Do NOT sum global
  snapshots across workers. Local frequency mode does not maintain a global population.
- `frequency_decisions`: scored non-null parents with POWER_COE on; `energy_decisions` also
  includes early-return cases. Sampling uses `frequency_decisions`.
- `frequency_{full_energy,downweighted}_decisions`: decision classifications.
- `frequency_candidate_energy`, `frequency_assigned_energy`, and `frequency_energy_removed`:
  sums of scheduler scores before and after frequency weighting. These are not executed
  mutations because outer-loop termination and discoveries can shorten a batch.
- `shared_downweights_local_would_full`: global weighting reduces a candidate that the
  worker-local population would leave unchanged. `shared_full_local_would_downweight` is the
  reverse disagreement. Neither simulates an independent run because histories diverge.
- `zero_energy_other`: candidate calculation or an early-return path assigned zero. Frequency
  weighting never turns a nonzero candidate into zero.

Events contain selected/local counts, population sizes, means, candidate energy, the
worker-local counterfactual energy, assigned energy and downweight flags. Assigned energy is
the score before any outer-loop early termination, not an executed-mutation count.

Global distinct traces are modulo buckets and frequencies can include collisions. The new
8-byte atomic observation total precedes the bucket array, reducing its size by two u32 slots;
the manager clears this layout before launching workers. Do not mix old and new workers in
one segment. The runner rebuilds the mounted sources together. Live atomic reads of total,
distinct count and individual bucket are separate, not a transactional snapshot; concurrent
updates can briefly produce inconsistent tuples. Existing u32 bucket frequencies retain their
4-billion-observation overflow limit; the population total is u64.

## Validation

Tests cover one-worker local/global equivalence, invariance to unrelated AFL executions,
replicated-worker energy, blended downweighting, both disagreement directions, the 75% energy
bound, empty populations, arithmetic boundaries, JSON sampling, concurrent process
increments, all four feedback configurations, and all eight launcher configurations.
Runner tests cover failures, shutdown, record preservation, no double-counting of global
snapshots, matched ablation seeds/order, reuse of one build across sixteen arms, locks, fingerprint drift, machine observations, and stopping on incomplete measurements or empty feedback. The local tests use dummy processes/artifacts; a container integration run is still required.

## Shutdown

The manager stays alive during group termination until workers finish. The schedule loop now respects stop requests even during zero-energy scanning. The runner allows five seconds of grace and retains periodic snapshots if forced termination prevents a final flush. Its final flags expose that limitation instead of presenting old stats as exact final values.

## Sharing modes

See EXPERIMENT_RECORDS.md for CLI options and paired comparisons. Worker schema 9 includes
frequency_mode, novelty_mode, and afl_sync. Event `selected_frequency_count` must be
interpreted with frequency_mode. Global uses modulo buckets,
local uses the existing Zig trace-hash map. The observational local table stays enabled in
both modes. Population and diagnostic changes are described above. No measured time-savings claim is added.


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
