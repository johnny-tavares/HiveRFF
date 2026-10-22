# Measurement semantics (runner schema 7, worker schema 6)

The standalone runner copies and rebuilds `afl-fuzz.c`, `mutator.zig`, `hive_metrics.h`, and `libsched.cpp` from period-wip, then compiles hivemind.c. No Docker image rebuild is required. Use the same mounted-file runner command as before. The ablation controller builds once for all arms, archives the artifacts, and checks fingerprints before and after trials. See EXPERIMENT_RECORDS.md for the controlled comparison commands.

## Files

Each worker writes atomic `hive_metrics.json` snapshots roughly once per second while making energy decisions or returning from schedule executions, plus a final snapshot on orderly shutdown. Long executions can delay publication. Each worker saves the first 1000 scored parents and every 1000th scored parent thereafter in `energy_decisions.jsonl`, including accepted and rejected parents. This is a systematic diagnostic sample, not a random or representative sample. Summary counters cover every decision.

The runner writes `timeline.jsonl` once per second with the latest published worker snapshots, and retains each snapshot's age. Trial `record.json` has separate `at_stop_request` and final snapshots; grace-period activity can appear only in the latter. `measurement_complete` requires all worker metrics to have final=true. `budget_completed` alone does not certify complete telemetry or prove all workers stayed healthy throughout.

## Runner schema 7

Worker counters and the population_mean_v1 scoring policy remain at schema 6. Schema 7
adds campaign build identity/verification and best-effort machine observations to the
Python records. Trial start/finish and each timeline sample include machine data; missing
fields are null. Container-visible host load, CPU ticks, memory, allowed CPUs, frequency
policy reports and cgroup-v2 counters are observations, not controlled experimental inputs.
The collector records its duration and adds read overhead. Frequency snapshots need not
be exact hardware execution frequencies. CPU tick guest fields overlap user/nice fields.

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

## Frequency policy: population_mean_v1

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

Schema 6 changes scheduling in BOTH local and global frequency modes. Rerun the local
baseline; schema 5 timings are historical context, not a comparison that isolates sharing.

The cutoff is `floor(selected normal schedule observations / selected distinct traces) + adj`
(with a minimum of one). Local mode uses the worker's normal observations and distinct trace
hashes; global mode uses atomic swarm normal observations and occupied frequency buckets.
The numerator now counts exactly the same `store_path_id` calls as the frequencies. It excludes
calibration, replay, crash, timeout, error and interrupted executions. The old numerator used
all worker-local AFL executions, even with global frequencies and distinct trace counts.

The cutoff determines parent eligibility. Batch energy remains on the worker-local scale in
both modes: `min(stage_max, floor(2^next_fuzz_level / local_threshold) * base_score)`.
Using the global threshold to divide batch energy too would shrink each worker's mutation
budget merely by duplicating otherwise identical workers. Arithmetic now uses 64-bit
intermediates and saturates the adjustment/threshold instead of wrapping.

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
- `frequency_rejections`: selected frequency exceeds its selected population cutoff.
- `shared_rejections_local_policy_would_pass`: global cutoff rejects but local frequency
  passes the worker-local cutoff. Both thresholds use the actual current `adj`.
- `shared_passes_local_policy_would_reject`: the reverse disagreement.
- `shared_frequency_rejections_local_would_pass`: retained old diagnostic comparing local
  frequency against the SAME selected cutoff; this can miss normalization effects.
- `frequency_rejections_local_also_fails`: complement of the old same-threshold diagnostic
  among rejections (also covers local operation).
- `zero_energy_other`: accepted/early-return scoring that assigns zero energy, including
  integer rounding. It is not evidence of avoiding duplicate work.
- `same_threshold_candidate_mutation_budget`: retained hypothetical score using the selected
  cutoff as energy denominator on old-style same-threshold rejections, capped by stage and
  remaining stage budgets. Actual policy energy uses the LOCAL cutoff. This legacy diagnostic
  is not work or time saved and is not the new local-policy candidate energy.

Events retain selected/local counts and add selected/local observation totals, trace counts,
both thresholds, adjustment, cutoff pass flags, and assigned score. `local_would_pass` now
literally tests the same selected cutoff on every sampled decision; `local_policy_would_pass`
tests the worker-local cutoff. A cutoff pass can still yield zero energy after integer division.
Assigned energy is the score before any outer-loop early termination, not executed mutations.

Neither diagnostic simulates an independent local run: history, parent selection, queues,
fuzz levels, adjustment and nondeterministic outcomes would diverge. Rejected parents are
not executed as probes. Whether their mutations would find bugs remains an experimental
question for ablations or a separately designed probe experiment.

Global distinct traces are modulo buckets and frequencies can include collisions. The new
8-byte atomic observation total precedes the bucket array, reducing its size by two u32 slots;
the manager clears this layout before launching workers. Do not mix old and new workers in
one segment. The runner rebuilds the mounted sources together. Live atomic reads of total,
distinct count and individual bucket are separate, not a transactional snapshot; concurrent
updates can briefly produce inconsistent tuples. Existing u32 bucket frequencies retain their
4-billion-observation overflow limit; the population total is u64.

## Validation

Tests cover one-worker local/global equivalence, invariance to unrelated AFL executions,
replicated-worker energy/acceptance, both disagreement directions, the missed-threshold
regression, empty populations, arithmetic boundaries, JSON sampling, concurrent process
increments, all four feedback configurations, and all eight launcher configurations.
Runner tests cover failures, shutdown, record preservation, no double-counting of global
snapshots, matched ablation seeds/order, reuse of one build across sixteen arms, locks, fingerprint drift, machine observations, and stopping on incomplete measurements or empty feedback. The local tests use dummy processes/artifacts; a container integration run is still required.

## Shutdown

The manager stays alive during group termination until workers finish. The schedule loop now respects stop requests even during zero-energy scanning. The runner allows five seconds of grace and retains periodic snapshots if forced termination prevents a final flush. Its final flags expose that limitation instead of presenting old stats as exact final values.

## Sharing modes

See EXPERIMENT_RECORDS.md for CLI options and paired comparisons. Worker schema 6 includes
frequency_mode, novelty_mode, and afl_sync. The rejection event count field is now
selected_frequency_count; interpret it with frequency_mode. Global uses modulo buckets,
local uses the existing Zig trace-hash map. The observational local table stays enabled in
both modes. Population and diagnostic changes are described above. No measured time-savings claim is added.
