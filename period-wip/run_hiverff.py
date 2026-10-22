import os
import sys
import time
import glob
import json
import subprocess
import resource
import shutil
import argparse
import shlex
from contextlib import contextmanager

# ==========================================
# CONFIGURATION
# ==========================================
TARGET_PROG = "/workdir/PERIOD/evaluation/CS/twostage_20/twostage_20_bad"
WORKERS = 16
# Fixed-duration trials retain exploration metrics and first-crash timing.
TIME_BUDGET = 120
MODE = "THROUGHPUT"
NUM_TRIALS = 5

FREQUENCY_MODE = "global"
NOVELTY_MODE = "shared"
AFL_SYNC = "off"  # Isolate feedback sharing from queue synchronization work.
SEED_BASE = 100
ALL_RFF_MODE = "inherit"

from pathlib import Path
from datetime import datetime, timezone
import hashlib
import signal
import fcntl
import uuid
import re

OUT_ROOT = Path("/opt/out")
MANAGER = "/opt/sched-fuzz/hivemind"
POLL_SECONDS = 0.05
SNAPSHOT_SECONDS = 1.0
SHUTDOWN_GRACE_SECONDS = 5.0
FREQUENCY_POLICY = "population_mean_v1"
FEEDBACK_IDENTITY_POLICY = "module_relative_stack_v2"

def utc_now():
    return datetime.now(timezone.utc).isoformat()

def save_json(path, data):
    temporary = path.with_suffix(".tmp")
    temporary.write_text(json.dumps(data, indent=2) + "\n")
    temporary.replace(path)

def fingerprint(path):
    path = Path(path)
    return hashlib.sha256(path.read_bytes()).hexdigest() if path.is_file() else None

def read_optional(path):
    try:
        return Path(path).read_text().strip()
    except (OSError, UnicodeError):
        return None


def machine_snapshot(proc=Path('/proc'), sys=Path('/sys')):
    """Read only aggregate machine counters; never collect processes or environment."""
    start = time.monotonic_ns()
    result = {'observed_at': utc_now(), 'monotonic_ns': start, 'load_average': None,
              'cpu_ticks': None, 'memory_kib': None, 'cpufreq': None, 'cgroup_v2': None}
    raw = read_optional(proc / 'loadavg')
    try:
        result['load_average'] = [float(v) for v in raw.split()[:3]] if raw else None
    except ValueError:
        pass
    raw = read_optional(proc / 'stat')
    if raw:
        for line in raw.splitlines():
            if line.startswith('cpu '):
                names = ('user','nice','system','idle','iowait','irq','softirq','steal','guest','guest_nice')
                try:
                    result['cpu_ticks'] = dict(zip(names, map(int, line.split()[1:])))
                except ValueError:
                    pass
                break
    raw = read_optional(proc / 'meminfo')
    if raw:
        values = {}
        for line in raw.splitlines():
            fields = line.split()
            if fields and fields[0].rstrip(':') in ('MemTotal','MemAvailable','SwapTotal','SwapFree'):
                try:
                    values[fields[0].rstrip(':')] = int(fields[1])
                except (ValueError, IndexError):
                    pass
        result['memory_kib'] = values or None
    try:
        result['allowed_cpus'] = sorted(os.sched_getaffinity(0))
    except (AttributeError, OSError):
        result['allowed_cpus'] = None
    result['logical_cpus'] = os.cpu_count()
    result['kernel_release'] = read_optional(proc / 'sys/kernel/osrelease')
    policies = {}
    try:
        for directory in sorted((sys / 'devices/system/cpu/cpufreq').glob('policy*')):
            policies[directory.name] = {name: read_optional(directory / name) for name in
                ('affected_cpus','scaling_driver','scaling_governor','scaling_cur_freq',
                 'cpuinfo_cur_freq','scaling_min_freq','scaling_max_freq')}
    except OSError:
        pass
    result['cpufreq'] = policies or None
    # Resolve the runner's v2 cgroup. Docker commonly exposes its cgroup as '/'.
    raw = read_optional(proc / 'self/cgroup')
    if raw:
        for line in raw.splitlines():
            if line.startswith('0::'):
                relative = Path(line[3:].lstrip('/'))
                if '..' not in relative.parts:
                    directory = sys / 'fs/cgroup' / relative
                    values = {name: read_optional(directory / name) for name in
                              ('cpu.max','cpu.stat','cpuset.cpus.effective','memory.current')}
                    if any(value is not None for value in values.values()):
                        result['cgroup_v2'] = values
                break
    result['collection_duration_ns'] = time.monotonic_ns() - start
    return result


def preflight():
    pattern = read_optional('/proc/sys/kernel/core_pattern')
    if pattern and pattern.startswith('|'):
        raise RuntimeError("Host kernel.core_pattern pipes crashes to a handler. Before fuzzing, save its original value and run 'sudo sysctl -w kernel.core_pattern=core' on the host. Restore it after the session. No host setting has been changed.")
    if os.environ.get('NO_RFF') not in (None, '0'):
        raise RuntimeError('NO_RFF disables schedule feedback; unset it before this comparison.')


def source_fingerprints():
    paths = [Path(__file__), Path(__file__).with_name('run_ablation.py')]
    paths += [Path('/opt/period-wip') / name for name in
              ('hivemind.c','mutator.zig','hive_metrics.h','afl-fuzz.c','libsched.cpp')]
    paths += [Path('/opt/sched-fuzz/AFL-2.57b') / name for name in ('afl-fuzz.c','hive_metrics.h')]
    paths.append(Path('/opt/sched-fuzz/libsched.cpp'))
    return {str(path): fingerprint(path) for path in paths}


def runtime_fingerprints():
    paths = [MANAGER, '/opt/sched-fuzz/AFL-2.57b/afl-fuzz', '/opt/sched-fuzz/libsched.so',
             '/opt/sched-fuzz/AFL-2.57b/mutator.zig', TARGET_PROG,
             '/opt/sched-fuzz/' + Path(TARGET_PROG).name + '.afl']
    return {path: fingerprint(path) for path in paths}


def seed_fingerprints():
    return {str(path): fingerprint(path) for path in sorted(Path('/opt/sched-fuzz/afl-in').glob('*'))
            if path.is_file()}


def prepare_build(directory):
    """Compile once under the campaign lock, retain artifacts, then freeze fingerprints."""
    directory.mkdir()
    with (directory / 'setup.log').open('w') as log:
        setup_environment(log)
    provenance = capture_provenance(directory)
    runtime = runtime_fingerprints()
    if not runtime or any(value is None for value in runtime.values()):
        raise RuntimeError('Build did not produce all required runtime artifacts.')
    inputs = {path: value['sha256'] for path, value in provenance['files'].items()}
    seeds = seed_fingerprints()
    archived = directory / 'artifacts'
    archived.mkdir()
    copies = {}
    for index, (path, expected) in enumerate(sorted(runtime.items())):
        copy = archived / ('%02d-' % index + Path(path).name)
        shutil.copy2(path, copy)
        if fingerprint(copy) != expected:
            raise RuntimeError('Runtime changed while archiving: ' + path)
        copies[path] = str(copy.relative_to(directory))
    build = {'schema_version': 7, 'target': TARGET_PROG, 'built_at': utc_now(),
             'frequency_policy': FREQUENCY_POLICY, 'source_sha256': source_fingerprints(),
             'feedback_identity_policy': FEEDBACK_IDENTITY_POLICY,
             'runtime_sha256': runtime, 'input_sha256': inputs, 'seed_sha256': seeds,
             'archived_runtime': copies,
             'target_provenance': provenance, 'directory': str(directory),
             'manifest_path': str(directory / 'build.json')}
    build['build_id'] = hashlib.sha256(json.dumps({'target':TARGET_PROG, 'runtime':runtime,
                                                 'inputs':inputs, 'seeds':seeds},sort_keys=True).encode()).hexdigest()
    save_json(directory / 'build.json', build)
    return build


def verify_build(build):
    if build['target'] != TARGET_PROG:
        raise RuntimeError('Prepared build target does not match this trial.')
    expected_runtime = build['runtime_sha256']
    if runtime_fingerprints() != expected_runtime:
        raise RuntimeError('Runtime artifacts changed after the shared build; stopping the comparison.')
    if source_fingerprints() != build['source_sha256']:
        raise RuntimeError('Sources changed after the shared build; stopping the comparison.')
    if seed_fingerprints() != build['seed_sha256']:
        raise RuntimeError('Seed corpus changed after the shared build; stopping the comparison.')
    for path, expected in build['input_sha256'].items():
        if fingerprint(path) != expected:
            raise RuntimeError('Build input changed after setup: ' + path)


def sharing_settings():
    return {"frequency": FREQUENCY_MODE, "novelty": NOVELTY_MODE, "afl_sync": AFL_SYNC}


def worker_seed_base(number):
    return SEED_BASE + (number - 1) * WORKERS


def configure_cli(argv=None):
    global TARGET_PROG, TIME_BUDGET, WORKERS, MODE, NUM_TRIALS, FREQUENCY_MODE, NOVELTY_MODE, AFL_SYNC, SEED_BASE, ALL_RFF_MODE
    parser = argparse.ArgumentParser(description="Run recorded HiveRFF experiments with independent sharing controls.")
    parser.add_argument("--target", default=TARGET_PROG,
                        help="Absolute PERIOD benchmark executable path; its .c and mempair.<name> files must be adjacent.")
    parser.add_argument("--seconds", type=float, default=TIME_BUDGET)
    parser.add_argument("--workers", type=int, default=WORKERS)
    parser.add_argument("--mode", choices=("throughput", "speed"), default=MODE.lower())
    parser.add_argument("--trials", type=int, default=NUM_TRIALS)
    parser.add_argument("--frequency", choices=("global", "local"), default=FREQUENCY_MODE)
    parser.add_argument("--novelty", choices=("shared", "local"), default=NOVELTY_MODE)
    parser.add_argument("--afl-sync", choices=("on", "off"), default=AFL_SYNC)
    parser.add_argument("--all-rff", choices=("inherit", "on", "off"), default=ALL_RFF_MODE,
                        help="Record all cross-thread reads-from feedback; inherit preserves the shell setting.")
    parser.add_argument("--seed-base", type=int, default=SEED_BASE,
                        help="Worker seeds start at base + 1; use the same base for paired comparisons.")
    args = parser.parse_args(argv)
    if not 0 < args.seconds < float("inf") or args.workers < 1 or args.trials < 1:
        parser.error("seconds must be finite and positive; workers and trials must be positive")
    if args.seed_base < 0 or args.seed_base + args.workers * args.trials > 2147483647:
        parser.error("worker seeds must fit a positive signed 32-bit integer")
    if not Path(args.target).is_absolute():
        parser.error("target must be an absolute path")
    ALL_RFF_MODE = args.all_rff
    TARGET_PROG = str(Path(args.target))
    TIME_BUDGET, WORKERS, MODE, NUM_TRIALS = args.seconds, args.workers, args.mode.upper(), args.trials
    FREQUENCY_MODE, NOVELTY_MODE, AFL_SYNC, SEED_BASE = args.frequency, args.novelty, args.afl_sync, args.seed_base


def capture_provenance(experiment):
    paths = [Path(TARGET_PROG + ".c"), Path(TARGET_PROG).with_name("mempair." + Path(TARGET_PROG).name),
             Path("/opt/sched-fuzz/out.csv")]
    destination = experiment / "target_inputs"
    destination.mkdir()
    files = {}
    for path in paths:
        files[str(path)] = {"sha256": fingerprint(path), "copy": None}
        if path.is_file():
            copy = destination / path.name
            shutil.copy2(path, copy)
            files[str(path)]["copy"] = str(copy.relative_to(experiment))
    revision = subprocess.run(["git", "-C", "/workdir/PERIOD", "rev-parse", "HEAD"],
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)
    return {"period_commit": revision.stdout.strip() if revision.returncode == 0 else None,
            "files": files}


def trial_settings(number, output):
    settings = {
        "TARGET_PROG": f"/opt/sched-fuzz/{Path(TARGET_PROG).name}.afl",
        "WORKERS": str(WORKERS), "FUZZERS": "power-coe-schedfuzz",
        "NUM_TRIALS": "1", "AFL_NO_AFFINITY": "1", "AFL_FAST_CAL": "1",
        "AFL_SKIP_CPUFREQ": "1",
        "SCHED_COUNTING": "1", "POWER_COE": "1", "DET_COV": "1",
        "AFL_PRELOAD": "/opt/sched-fuzz/libsched.so",
        "ASAN_OPTIONS": "abort_on_error=1:symbolize=0:detect_leaks=0:disable_coredump=1",
        "TRIAL_NUM": str(number), "HIVE_OUTPUT_DIR": str(output),
        "HIVE_FREQUENCY_MODE": FREQUENCY_MODE, "HIVE_NOVELTY_MODE": NOVELTY_MODE,
        "HIVE_AFL_SYNC": AFL_SYNC, "HIVE_SEED_BASE": str(worker_seed_base(number)),
    }
    if ALL_RFF_MODE != "inherit":
        settings["ALL_RFF"] = "1" if ALL_RFF_MODE == "on" else "0"
    # Preserve the existing mode-specific setting; make it visible in the record.
    if MODE == "THROUGHPUT":
        settings["MASK"] = "0x3FFF"
    return settings

def setup_environment(log):
    def run(*args, **kwargs):
        return subprocess.run(*args, stdout=log, stderr=subprocess.STDOUT, **kwargs)
    print("[*] Phase 1: Native Compilation & Instrumentation...")
    try:
        # Prevent 16TB ASAN Core Dumps from destroying disk I/O
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0)) 
        resource.setrlimit(resource.RLIMIT_NOFILE, (65535, 65535))
    except Exception as e:
        print("Couldn't set limit")
        pass
    run("cp /opt/period-wip/libsched.cpp /opt/sched-fuzz/libsched.cpp && cp /opt/period-wip/mutator.zig /opt/period-wip/afl-fuzz.c /opt/period-wip/hive_metrics.h /opt/sched-fuzz/AFL-2.57b/ && cd /opt/sched-fuzz/AFL-2.57b && make", shell=True, check=True)
    run("gcc -O3 /opt/period-wip/hivemind.c -o /opt/sched-fuzz/hivemind -lrt", shell=True, check=True)
    print("    [+] Setting up dummy seed...")
    run("rm -rf /opt/sched-fuzz/afl-in", shell=True)
    run("mkdir -p /opt/sched-fuzz/afl-in", shell=True)
    run("echo 'hi' > /opt/sched-fuzz/afl-in/hi.txt", shell=True)

    # --- SELECTIVE INSTRUMENTATION (Static-PP) ---
    print("    [+] Extracting memory pairs for selective instrumentation...")
    src_root = os.path.dirname(TARGET_PROG)
    stem = TARGET_PROG.split("/")[-1]
    quoted_root = shlex.quote(src_root)
    quoted_target = shlex.quote(TARGET_PROG)
    quoted_pairs = shlex.quote(f"{src_root}/mempair.{stem}")

    run(
        f"cd /opt/sched-fuzz && python3 get-offsets-from-mempairs.py {quoted_pairs} {quoted_target} {quoted_root}",
        shell=True, check=True
    )

    print("    [+] Injecting selective RFF schedule instrumentation...")
    run(
        f"cd /opt/sched-fuzz && ./selective-instrument.sh {quoted_target} out.csv",
        shell=True, check=True
    )

def snapshot(output):
    workers = {}
    crashes = []
    for number in range(WORKERS):
        directory = output / f"worker_{number}"
        stats = {}
        try:
            for line in (directory / "fuzzer_stats").read_text().splitlines():
                key, separator, value = line.partition(":")
                if separator:
                    stats[key.strip()] = value.strip()
        except OSError:
            pass
        try:
            schedules = int((directory / "num_scheds.txt").read_text().strip())
        except (OSError, ValueError):
            schedules = None
        try:
            metrics = json.loads((directory / "hive_metrics.json").read_text())
        except (OSError, ValueError):
            metrics = None
        try:
            stats_age = max(0, time.time() - int(stats["last_update"]))
        except (KeyError, ValueError):
            stats_age = None
        metrics_age = (max(0, time.monotonic_ns() - metrics["published_monotonic_ns"]) / 1e9
                       if metrics and "published_monotonic_ns" in metrics else None)
        workers[directory.name] = {"legacy_mutation_counter": schedules, "fuzzer_stats": stats,
                                  "fuzzer_stats_age_sec": stats_age,
                                  "metrics": metrics, "metrics_age_sec": metrics_age}
        for pattern in ("crashes/id*", "scheds/*/crash-*"):
            crashes.extend(str(p.relative_to(output)) for p in directory.glob(pattern) if p.is_file())
    counts = [worker["legacy_mutation_counter"] for worker in workers.values()]
    complete = all(w["metrics"] and w["metrics"].get("final") for w in workers.values())
    counter_names = ("mutations_generated", "schedule_executions_started", "schedule_executions_completed",
                     "schedule_executions_interrupted", "crash_returns", "timeout_returns", "error_returns",
                     "normal_returns", "completed_execution_wall_ns", "energy_decisions", "frequency_rejections",
                     "shared_frequency_rejections_local_would_pass", "frequency_rejections_local_also_fails",
                     "zero_energy_other", "same_threshold_candidate_mutation_budget",
                     "local_frequency_observations", "frequency_decisions",
                     "shared_rejections_local_policy_would_pass", "shared_passes_local_policy_would_reject",
                     "code_novelty_returns", "rf_only_novelty_returns",
                     "worker_unique_completed_trace_hashes", "worker_unique_normal_trace_hashes",
                     "worker_unique_crash_trace_hashes", "worker_unique_timeout_trace_hashes",
                     "worker_unique_error_trace_hashes", "schedule_bitmap_empty_returns",
                     "schedule_bitmap_nonempty_returns")
    totals = {}
    for key in counter_names:
        values = [w["metrics"].get(key) if w["metrics"] else None for w in workers.values()]
        totals[key] = sum(values) if all(isinstance(v, int) for v in values) else None
    return {"workers": workers, "crash_files": sorted(crashes),
            "crash_file_count": len(crashes), "all_worker_metrics_final": complete,
            "totals": totals,
            "legacy_mutations_generated": sum(counts) if all(c is not None for c in counts) else None}


def stop_trial(process):
    # Stop only the process group created by this trial, including its workers.
    try:
        os.killpg(process.pid, signal.SIGTERM)
    except ProcessLookupError:
        pass
    try:
        process.wait(timeout=SHUTDOWN_GRACE_SECONDS)
    except subprocess.TimeoutExpired:
        pass
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    process.wait()


def run_trial(experiment, number):
    directory = experiment / f"trial-{number:03d}"
    output = directory / "afl"
    output.mkdir(parents=True)
    settings = trial_settings(number, output)
    env = os.environ.copy()
    env.update(settings)
    # Record relevant inherited overrides without dumping unrelated secrets.
    effective = {k: v for k, v in env.items() if k.startswith("AFL_") or k in
                 set(settings) | {"MASK", "SEED", "LD_PRELOAD", "SCHEDULE", "HIVEMIND_SHM",
                                  "ALL_RFF", "RECORD_EXACT_RFS"}}
    record = {"schema_version": 7, "trial": number, "mode": MODE,
              "status": "running", "started_at": utc_now(), "sharing": sharing_settings(), "frequency_policy": FREQUENCY_POLICY,
              "feedback_identity_policy": FEEDBACK_IDENTITY_POLICY,
              "time_budget_sec": TIME_BUDGET, "environment": effective,
              "worker_seeds": {f"worker_{i}": i + 1 + worker_seed_base(number) for i in range(WORKERS)},
              "first_crash_observed_sec": None,
              "machine_before": machine_snapshot(),
              "timing_definition": "Monotonic seconds from manager launch; includes worker startup. Crash time is first polling observation, not exact fault time.",
              "poll_interval_sec": POLL_SECONDS,
              "snapshot_interval_sec": SNAPSHOT_SECONDS,
              "measurement_definitions": {
                  "mutations_generated": "Mutant schedules returned by sched_mutate; not executions or unique traces.",
                  "schedule_executions_completed": "run_target returned without shutdown requested, within sched_fuzz_stuff; includes normal, crash, timeout and error outcomes. Excludes calibration/replay executions.",
                  "worker_unique_outcome_trace_hashes": "Distinct schedule-map hashes observed by each worker, split by outcome. Trial totals sum worker-local cardinalities and can count the same hash once per worker; hashes are not exact schedule identities.",
                  "schedule_bitmap_empty_returns": "Completed schedule executions whose schedule-map hash equals the hash of an all-zero schedule bitmap. Nonempty returns are counted separately; hash collisions are theoretically possible.",
                  "shared_frequency_rejections_local_would_pass": "Observed global bucket count exceeds the current threshold while this worker's own trace-hash count does not. Same-threshold diagnostic; not a standalone-worker counterfactual. Global bucket/hash collisions may contribute.",
                  "same_threshold_candidate_mutation_budget": "Sum of hypothetical local-count energy at those rejection decisions, capped by remaining stage budget. Not actual mutations saved: early discoveries can shorten batches and parents may be revisited.",
                  "frequency_policy": "population_mean_v1: frequency cutoff=floor(normal schedule observations/distinct traces)+adjustment, all from the selected local/global population. Energy uses the worker-local threshold in both modes. Both modes changed from schema 5; rerun the local baseline.",
                  "population_snapshots": "selected_frequency_observations and selected_frequency_trace_buckets are global when frequency=global; do not sum them across workers. Live atomic fields can be briefly inconsistent. Local mode has no global population. Global distinct traces are occupied modulo buckets.",
                  "shared_rejections_local_policy_would_pass": "Global cutoff rejects but local frequency passes the worker-local threshold. Observed parent, history and adjustment are held fixed; not an independent local run or time saved.",
                  "shared_passes_local_policy_would_reject": "Global cutoff passes but local frequency exceeds the worker-local threshold; same observed-history limitation.",
                  "decision_events": "First 1000 scored parents, then every 1000th, including accepted and rejected decisions. Systematic diagnostic sample, not random. Totals cover all decisions.",
                  "machine_conditions": "Best-effort container-visible /proc and /sys observations at start, each timeline sample, and finish. Missing fields are null. Load/CPU ticks may describe the whole host; cpufreq values are driver-reported snapshots, not exact execution frequencies. Cgroup fields refer to the runner cgroup when accessible. Observation duration and sampled reads add some measurement overhead; no machine settings are changed.",
                  "time_saved": "Not measured. completed_execution_wall_ns sums worker execution durations, not swarm wall time saved.",
                  "final_totals": "May include shutdown-grace activity. Use at_stop_request and timeline.jsonl for periodic observations before shutdown. Check final flags and snapshot ages."},
              "crash_count_definition": "Artifact files, not deduplicated or validated bugs."}
    save_json(directory / "record.json", record)
    process = None
    record["launch_monotonic_ns"] = time.monotonic_ns()
    started = record["launch_monotonic_ns"] / 1e9
    save_json(directory / "record.json", record)
    interrupted = False
    next_snapshot = 0.0
    try:
        with (directory / "console.log").open("w") as log:
            process = subprocess.Popen([MANAGER], env=env, stdout=log,
                                       stderr=subprocess.STDOUT, start_new_session=True)
            while True:
                elapsed = time.monotonic() - started
                has_crash = any(output.glob("worker_*/crashes/id*")) or any(output.glob("worker_*/scheds/*/crash-*"))
                if has_crash and record["first_crash_observed_sec"] is None:
                    record["first_crash_observed_sec"] = elapsed
                    save_json(directory / "record.json", record)
                if elapsed >= next_snapshot:
                    observed = snapshot(output)
                    observed.pop("crash_files", None)
                    with (directory / "timeline.jsonl").open("a") as timeline:
                        timeline.write(json.dumps({"elapsed_sec": elapsed, "machine": machine_snapshot(), **observed}) + "\n")
                    next_snapshot = elapsed + SNAPSHOT_SECONDS
                exit_code = process.poll()
                if exit_code is not None:
                    record.update(status="failed", error="Manager exited before the trial stopping condition.",
                                  manager_exit_code_before_stop=exit_code)
                    break
                if MODE == "SPEED" and record["first_crash_observed_sec"] is not None:
                    record["status"] = "crash_found"
                    break
                if elapsed >= TIME_BUDGET:
                    record["status"] = "timeout" if MODE == "SPEED" else "budget_completed"
                    break
                time.sleep(POLL_SECONDS)
    except KeyboardInterrupt:
        record["status"] = "interrupted"
        interrupted = True
    except Exception as exc:
        record.update(status="failed", error=str(exc))
    finally:
        record["observation_duration_sec"] = time.monotonic() - started
        record["at_stop_request"] = snapshot(output)
        record["shutdown_grace_sec"] = SHUTDOWN_GRACE_SECONDS
        if process is not None:
            stop_trial(process)
            record["manager_returncode_after_stop"] = process.returncode
        record.update(snapshot(output))
        record["machine_after"] = machine_snapshot()
        record["finished_at"] = utc_now()
        record["measurement_complete"] = record["all_worker_metrics_final"]
        if not record["measurement_complete"]:
            record["measurement_warning"] = "Some workers did not publish final metrics; retained snapshots may be stale or incomplete."
        log_path = directory / "console.log"
        if log_path.exists():
            text = re.sub(r"\x1b\[[0-9;?]*[A-Za-z]", "", log_path.read_text(errors="replace"))
            record["worker_abort_reasons"] = sorted(set(re.findall(r"PROGRAM ABORT\s*:\s*([^\n]+)", text)))
        record["missing_worker_stats"] = [k for k, v in record["workers"].items() if not v["fuzzer_stats"]]
        if record["missing_worker_stats"] and record["status"] in ("timeout", "budget_completed"):
            record.update(status="failed", error="One or more workers produced no fuzzer_stats; inspect console.log.")
        save_json(directory / "record.json", record)
    print(f"Trial {number}: {record['status']} — {directory}")
    for reason in record.get("worker_abort_reasons", []):
        print(f"  Worker error: {reason}")
    if not record["measurement_complete"]:
        print("  Measurement incomplete: check record.json final flags and console.log.")
    if interrupted:
        raise KeyboardInterrupt
    return record


@contextmanager
def experiment_lock():
    OUT_ROOT.mkdir(parents=True, exist_ok=True)
    with (OUT_ROOT / ".hiverff.lock").open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        yield


def run_experiment(prepared=None):
    """Run while experiment_lock is held by the standalone runner or controller."""
    if MODE not in ("SPEED", "THROUGHPUT") or WORKERS < 1 or TIME_BUDGET <= 0 or NUM_TRIALS < 1:
        raise ValueError("Invalid experiment configuration")
    name = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ") + "-" + uuid.uuid4().hex[:8]
    experiment = OUT_ROOT / "experiments" / name
    experiment.mkdir(parents=True)
    planned = NUM_TRIALS
    manifest = {"schema_version": 7, "status": "setting_up", "started_at": utc_now(),
                "target": TARGET_PROG, "mode": MODE, "workers": WORKERS,
                "time_budget_sec": TIME_BUDGET, "planned_trials": planned,
                "configured_num_trials": NUM_TRIALS, "sharing": sharing_settings(), "frequency_policy": FREQUENCY_POLICY, "seed_base": SEED_BASE,
                "feedback_identity_policy": FEEDBACK_IDENTITY_POLICY,
                "source_sha256": {}, "trials": []}
    manifest["source_sha256"] = source_fingerprints()
    save_json(experiment / "experiment.json", manifest)
    print(f"Experiment records: {experiment}", flush=True)
    print(f"{MODE}: {WORKERS} workers, {TIME_BUDGET:g}s, {planned} trial(s); sharing={sharing_settings()}", flush=True)
    try:
        if prepared is None:
            with (experiment / "setup.log").open("w") as log:
                setup_environment(log)
            manifest["target_provenance"] = capture_provenance(experiment)
            manifest["runtime_sha256"] = runtime_fingerprints()
            manifest["source_sha256"] = source_fingerprints()
        else:
            verify_build(prepared)
            manifest.update({key: prepared[key] for key in
                             ("build_id", "source_sha256", "runtime_sha256", "target_provenance")})
            manifest["build_manifest"] = prepared["manifest_path"]
            manifest["build_reused"] = True
            manifest["build_verification_before"] = "passed"
            shutil.copytree(Path(prepared["directory"]) / "target_inputs", experiment / "target_inputs")
            (experiment / "setup.log").write_text("Reused verified build: " + prepared["manifest_path"] + "\n")
        manifest["status"] = "running"
        save_json(experiment / "experiment.json", manifest)
        for number in range(1, planned + 1):
            if prepared is not None:
                verify_build(prepared)
            result = run_trial(experiment, number)
            manifest["trials"].append({"trial": number, "status": result["status"],
                                      "record": f"trial-{number:03d}/record.json"})
            save_json(experiment / "experiment.json", manifest)
            if prepared is not None:
                verify_build(prepared)
                manifest["build_verification_after"] = "passed"
        manifest["status"] = "completed_with_failures" if any(t["status"] == "failed" for t in manifest["trials"]) else "completed"
    except KeyboardInterrupt:
        manifest["status"] = "interrupted"
    except Exception as exc:
        manifest.update(status="failed", error=str(exc))
        raise
    finally:
        manifest["finished_at"] = utc_now()
        save_json(experiment / "experiment.json", manifest)
    return experiment, manifest


def main():
    with experiment_lock():
        return run_experiment()


def handle_termination(signum, frame):
    raise KeyboardInterrupt


if __name__ == "__main__":
    signal.signal(signal.SIGTERM, handle_termination)
    configure_cli()
    main()
