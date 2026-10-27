/* Per-worker observations and population-consistent schedule policy helpers. */
#ifndef HIVE_METRICS_H
#define HIVE_METRICS_H
#include <stdint.h>
#include <inttypes.h>

typedef struct { uint32_t key; uint64_t count; int used; } hive_slot;
typedef struct { hive_slot *slots; size_t capacity, used; } hive_unique_table;
static hive_slot *hive_local;
static size_t hive_capacity, hive_used;
static hive_unique_table hive_completed_traces, hive_normal_traces, hive_crash_traces;
static hive_unique_table hive_timeout_traces, hive_error_traces;
static FILE *hive_events;
static int hive_shared_enabled;
static uint64_t hive_last_publish, hive_event_rows;
static uint64_t hive_generated, hive_started, hive_completed, hive_interrupted;
static uint64_t hive_normal, hive_crashes, hive_timeouts, hive_errors;
static uint64_t hive_exec_ns, hive_decisions;
static uint64_t hive_frequency_observations, hive_frequency_decisions;
static uint64_t hive_downweighted, hive_full_energy;
static uint64_t hive_energy_before, hive_energy_after, hive_energy_removed;
static uint64_t hive_shared_downweight_local_full, hive_shared_full_local_downweight;
static uint64_t hive_zero_other;
static uint64_t hive_preprocess_runs, hive_preprocess_failures;
static uint64_t hive_pair_loads, hive_pair_empty_loads, hive_pair_last_count, hive_pair_available;
static uint64_t hive_mutation_obligations, hive_mutation_seed, hive_mutation_flags;
static uint64_t hive_mutation_unchanged, hive_mutation_initial, hive_mutation_with_obligations;
static uint64_t hive_cov_novel, hive_rf_novel;
static uint64_t hive_empty_sched_map_returns, hive_nonempty_sched_map_returns;
static uint32_t hive_empty_sched_map_hash, hive_first_completed_trace_hash;
static int hive_empty_sched_map_hash_ready, hive_first_completed_trace_hash_ready;

/* Integer arithmetic with defined empty-population and overflow behavior. */
static uint64_t hive_threshold(uint64_t observations, uint64_t paths, uint64_t adjustment) {
  uint64_t mean = observations / (paths ? paths : 1);
  if (UINT64_MAX - mean < adjustment) return UINT64_MAX;
  uint64_t result = mean + adjustment;
  return result ? result : 1;
}

static uint32_t hive_energy(uint32_t level, uint64_t threshold, uint32_t base, uint32_t cap) {
  uint64_t factor = (UINT64_C(1) << (level < 31 ? level : 31)) / (threshold ? threshold : 1);
  uint64_t energy = factor * base; /* <= 2^31 * (2^32 - 1). */
  return energy > cap ? cap : (uint32_t)energy;
}

/* Blend three parts full energy with one part proportional energy. Retain
   at least 75% of each candidate while favoring relatively rare traces. */
static uint32_t hive_frequency_energy(uint32_t candidate, uint64_t count,
                                      uint64_t threshold) {
  if (!candidate || count <= threshold) return candidate;
  __uint128_t denominator = (__uint128_t)count * 4;
  __uint128_t weight = (__uint128_t)count * 3 + threshold;
  __uint128_t numerator = (__uint128_t)candidate * weight + denominator - 1;
  return (uint32_t)(numerator / denominator);
}

static uint64_t hive_now_ns(void) {
  struct timespec t;
  if (clock_gettime(CLOCK_MONOTONIC, &t)) PFATAL("clock_gettime");
  return (uint64_t)t.tv_sec * 1000000000ULL + t.tv_nsec;
}

/* Optional diagnostics; independent of scheduler scores and PRNG state. */
static int hive_profile_enabled;
static uint64_t hive_profile_origin, hive_profile_rows, hive_profile_dropped;
static FILE *hive_profile_file;
#define HIVE_PROFILE_LIMIT 100000
#define HIVE_PROFILE_TIMERS(X) \
  X(selection) X(mutation) X(schedule_write) X(target_wall) X(target_parent_cpu) \
  X(novelty) X(frequency_update) X(local_observe) X(diagnostics)
#define HIVE_PROFILE_DECLARE(name) static uint64_t hive_profile_##name##_ns, hive_profile_##name##_calls;
HIVE_PROFILE_TIMERS(HIVE_PROFILE_DECLARE)
#undef HIVE_PROFILE_DECLARE
#define HIVE_PROFILE_START() (hive_profile_enabled ? hive_now_ns() : 0)
#define HIVE_PROFILE_END(name, start) do { if (hive_profile_enabled) { \
  hive_profile_##name##_ns += hive_now_ns() - (start); \
  ++hive_profile_##name##_calls; } } while (0)

static uint64_t hive_parent_cpu_ns(void) {
  struct timespec t;
  if (clock_gettime(CLOCK_THREAD_CPUTIME_ID, &t)) PFATAL("profile CPU clock");
  return (uint64_t)t.tv_sec * 1000000000ULL + t.tv_nsec;
}

static void hive_profile_configure(void) {
  const char *v = getenv("HIVE_PROFILE");
  if (v && strcmp(v,"0") && strcmp(v,"1")) FATAL("HIVE_PROFILE must be 0 or 1");
  hive_profile_enabled = v && !strcmp(v,"1");
  if (hive_profile_enabled) hive_profile_origin = hive_now_ns();
}

/* FNV-1a on canonical little-endian fields. Never hash pointers or padding.
   These are fingerprints of schedule specifications, not actual interleavings. */
static uint64_t hive_profile_word(uint64_t hash, uint64_t value) {
  for (unsigned i=0; i<8; ++i) {
    hash ^= (uint8_t)value; hash *= UINT64_C(1099511628211); value >>= 8;
  }
  return hash;
}
static uint64_t hive_profile_schedule(const Sched *s, int include_seed) {
  uint64_t h = UINT64_C(14695981039346656037);
  h = hive_profile_word(h, s ? 1 : 0);
  if (!s) return h;
  if (include_seed) h = hive_profile_word(h, s->random_seed);
  h = hive_profile_word(h, s->delay);
  h = hive_profile_word(h, s->dist);
  h = hive_profile_word(h, s->avoid_uninit_writes);
  h = hive_profile_word(h, s->pos_len);
  h = hive_profile_word(h, s->neg_len);
  for (size_t i=0; i<s->pos_len+s->neg_len; ++i) {
    h = hive_profile_word(h, s->obligations[i].r);
    h = hive_profile_word(h, s->obligations[i].w);
  }
  return h;
}
static uint64_t hive_profile_input(const u8 *data, size_t len) {
  uint64_t h=UINT64_C(14695981039346656037);
  for (size_t i=0; i<len; ++i) { h ^= data[i]; h *= UINT64_C(1099511628211); }
  return h;
}
static void hive_profile_row(const char *kind, const struct sched_entry *parent,
                             const struct sched_entry *child, uint64_t input_hash,
                             uint32_t value, int interrupted) {
  if (!hive_profile_enabled) return;
  uint64_t begin=hive_now_ns();
  if (hive_profile_rows >= HIVE_PROFILE_LIMIT) {
    ++hive_profile_dropped; HIVE_PROFILE_END(diagnostics,begin); return;
  }
  if (!hive_profile_file) {
    char path[4096];
    if (snprintf(path,sizeof path,"%s/profile.jsonl",out_dir) >= sizeof path)
      FATAL("Profile output path too long");
    hive_profile_file=fopen(path,"w");
    if (!hive_profile_file) PFATAL("Open profile output");
  }
  const Sched *schedule=child ? child->sched : (parent ? parent->sched : NULL);
  if (fprintf(hive_profile_file,
      "{\"schema_version\":1,\"kind\":\"%s\",\"elapsed_ns\":%" PRIu64
      ",\"input_hash\":\"%016" PRIx64 "\",\"parent_hash\":\"%016" PRIx64
      "\",\"schedule_hash\":\"%016" PRIx64 "\",\"shape_hash\":\"%016" PRIx64
      "\",\"parent_present\":%s,\"parent_trace\":%u,\"value\":%u,\"interrupted\":%s"
      ",\"outcome_trace\":%u}\n",
      kind,begin-hive_profile_origin,input_hash,
      hive_profile_schedule(parent ? parent->sched : NULL,1),
      hive_profile_schedule(schedule,1),hive_profile_schedule(schedule,0),
      parent ? "true":"false",parent ? parent->sched_trace_id:0,value,
      interrupted ? "true":"false",
      child && !interrupted ? hash32(trace_bits+MAP_SIZE,SCHED_MAP_SIZE,8):0)<0)
    PFATAL("Write profile output");
  ++hive_profile_rows;
  HIVE_PROFILE_END(diagnostics,begin);
}

static size_t hive_index(uint32_t key, size_t capacity) {
  return ((uint64_t)key * 2654435761U) & (capacity - 1);
}

static void hive_grow(void) {
  size_t old_capacity = hive_capacity;
  hive_slot *old = hive_local;
  hive_capacity = old_capacity ? old_capacity * 2 : 1024;
  hive_local = calloc(hive_capacity, sizeof(*hive_local));
  if (!hive_local) PFATAL("Hive local observation allocation");
  for (size_t i = 0; i < old_capacity; ++i) if (old[i].used) {
    size_t j = hive_index(old[i].key, hive_capacity);
    while (hive_local[j].used) j = (j + 1) & (hive_capacity - 1);
    hive_local[j] = old[i];
  }
  free(old);
}

static void hive_observe(uint32_t key) {
  if (!hive_capacity || (hive_used + 1) * 2 >= hive_capacity) hive_grow();
  size_t i = hive_index(key, hive_capacity);
  while (hive_local[i].used && hive_local[i].key != key) i = (i + 1) & (hive_capacity - 1);
  if (!hive_local[i].used) {
    hive_local[i].used = 1; hive_local[i].key = key; ++hive_used;
  }
  ++hive_local[i].count;
  ++hive_frequency_observations;
}

static uint64_t hive_local_count(uint32_t key) {
  if (!hive_capacity) return 0;
  size_t i = hive_index(key, hive_capacity);
  while (hive_local[i].used) {
    if (hive_local[i].key == key) return hive_local[i].count;
    i = (i + 1) & (hive_capacity - 1);
  }
  return 0;
}

static void hive_unique_grow(hive_unique_table *table) {
  size_t old_capacity = table->capacity;
  hive_slot *old = table->slots;
  table->capacity = old_capacity ? old_capacity * 2 : 1024;
  table->slots = calloc(table->capacity, sizeof(*table->slots));
  if (!table->slots) PFATAL("Hive unique trace allocation");
  for (size_t i = 0; i < old_capacity; ++i) if (old[i].used) {
    size_t j = hive_index(old[i].key, table->capacity);
    while (table->slots[j].used) j = (j + 1) & (table->capacity - 1);
    table->slots[j] = old[i];
  }
  free(old);
}

static void hive_unique_observe(hive_unique_table *table, uint32_t key) {
  if (!table->capacity || (table->used + 1) * 2 >= table->capacity) hive_unique_grow(table);
  size_t i = hive_index(key, table->capacity);
  while (table->slots[i].used && table->slots[i].key != key)
    i = (i + 1) & (table->capacity - 1);
  if (!table->slots[i].used) {
    table->slots[i].used = 1;
    table->slots[i].key = key;
    ++table->used;
  }
}

static void hive_publish(int final) {
  uint64_t now = hive_now_ns();
  if (!final && now - hive_last_publish < 1000000000ULL) return;
  hive_last_publish = now;
  if (hive_profile_file) {
    uint64_t begin=hive_now_ns();
    if (fflush(hive_profile_file)) PFATAL("Flush profile output");
    HIVE_PROFILE_END(diagnostics,begin);
  }
  char temporary[4096], destination[4096];
  if (snprintf(temporary, sizeof temporary, "%s/hive_metrics.json.tmp", out_dir) >= sizeof temporary ||
      snprintf(destination, sizeof destination, "%s/hive_metrics.json", out_dir) >= sizeof destination)
    FATAL("Hive metrics output path too long");
  FILE *f = fopen(temporary, "w");
  if (!f) PFATAL("Open Hive metrics");
  fprintf(f, "{\"schema_version\":11,\"final\":%s,\"published_monotonic_ns\":%" PRIu64,
          final ? "true" : "false", now);
  fprintf(f, ",\"frequency_mode\":\"%s\",\"novelty_mode\":\"%s\",\"afl_sync\":\"%s\"",
          hive_shared_enabled ? "global" : "local", hive_novelty_shared ? "shared" : "local",
          sync_id ? "on" : "off");
#define HIVE_FIELD(label, value) fprintf(f, ",\"" label "\":%" PRIu64, (uint64_t)(value))
  fprintf(f, ",\"frequency_policy\":\"guarded_frequency_energy_v4\"");
  fprintf(f, ",\"profiling_enabled\":%s,\"profiling_policy\":\"phase_timing_schedule_fingerprints_v1\"",
          hive_profile_enabled ? "true" : "false");
  HIVE_FIELD("profile_rows", hive_profile_rows);
  HIVE_FIELD("profile_dropped_rows", hive_profile_dropped);
  HIVE_FIELD("profile_elapsed_ns", hive_profile_enabled ? now-hive_profile_origin : 0);
#define HIVE_PROFILE_FIELD(name) HIVE_FIELD("profile_" #name "_ns", hive_profile_##name##_ns); HIVE_FIELD("profile_" #name "_calls", hive_profile_##name##_calls);
  HIVE_PROFILE_TIMERS(HIVE_PROFILE_FIELD)
#undef HIVE_PROFILE_FIELD
  fprintf(f, ",\"preprocessing_policy\":\"checked_worker_local_pairs_v1\"");
  HIVE_FIELD("preprocess_runs", hive_preprocess_runs);
  HIVE_FIELD("preprocess_failures", hive_preprocess_failures);
  HIVE_FIELD("pair_loads", hive_pair_loads);
  HIVE_FIELD("pair_empty_loads", hive_pair_empty_loads);
  HIVE_FIELD("pair_last_count", hive_pair_last_count);
  HIVE_FIELD("pair_available", hive_pair_available);
  HIVE_FIELD("mutation_obligation_changes", hive_mutation_obligations);
  HIVE_FIELD("mutation_seed_changes", hive_mutation_seed);
  HIVE_FIELD("mutation_flag_changes", hive_mutation_flags);
  HIVE_FIELD("mutation_unchanged", hive_mutation_unchanged);
  HIVE_FIELD("mutation_initial_schedules", hive_mutation_initial);
  HIVE_FIELD("mutation_with_obligations", hive_mutation_with_obligations);
  HIVE_FIELD("local_frequency_observations", hive_frequency_observations);
  HIVE_FIELD("selected_frequency_observations", total_path_observations());
  HIVE_FIELD("selected_frequency_trace_buckets", total_paths());
  HIVE_FIELD("frequency_decisions", hive_frequency_decisions);
  HIVE_FIELD("frequency_downweighted_decisions", hive_downweighted);
  HIVE_FIELD("frequency_full_energy_decisions", hive_full_energy);
  HIVE_FIELD("frequency_candidate_energy", hive_energy_before);
  HIVE_FIELD("frequency_assigned_energy", hive_energy_after);
  HIVE_FIELD("frequency_energy_removed", hive_energy_removed);
  HIVE_FIELD("shared_downweights_local_would_full", hive_shared_downweight_local_full);
  HIVE_FIELD("shared_full_local_would_downweight", hive_shared_full_local_downweight);
  HIVE_FIELD("mutations_generated", hive_generated);
  HIVE_FIELD("schedule_executions_started", hive_started);
  HIVE_FIELD("schedule_executions_completed", hive_completed);
  HIVE_FIELD("schedule_executions_interrupted", hive_interrupted);
  HIVE_FIELD("normal_returns", hive_normal);
  HIVE_FIELD("crash_returns", hive_crashes);
  HIVE_FIELD("timeout_returns", hive_timeouts);
  HIVE_FIELD("error_returns", hive_errors);
  HIVE_FIELD("completed_execution_wall_ns", hive_exec_ns);
  HIVE_FIELD("energy_decisions", hive_decisions);
  HIVE_FIELD("zero_energy_other", hive_zero_other);
  HIVE_FIELD("code_novelty_returns", hive_cov_novel);
  HIVE_FIELD("rf_only_novelty_returns", hive_rf_novel);
  HIVE_FIELD("decision_events_written", hive_event_rows);
  HIVE_FIELD("local_observed_trace_hashes", hive_used);
  HIVE_FIELD("worker_unique_completed_trace_hashes", hive_completed_traces.used);
  HIVE_FIELD("worker_unique_normal_trace_hashes", hive_normal_traces.used);
  HIVE_FIELD("worker_unique_crash_trace_hashes", hive_crash_traces.used);
  HIVE_FIELD("worker_unique_timeout_trace_hashes", hive_timeout_traces.used);
  HIVE_FIELD("worker_unique_error_trace_hashes", hive_error_traces.used);
  HIVE_FIELD("schedule_bitmap_empty_returns", hive_empty_sched_map_returns);
  HIVE_FIELD("schedule_bitmap_nonempty_returns", hive_nonempty_sched_map_returns);
  HIVE_FIELD("empty_schedule_bitmap_hash", hive_empty_sched_map_hash);
  HIVE_FIELD("first_completed_trace_hash", hive_first_completed_trace_hash);
#undef HIVE_FIELD
  if (fprintf(f, "}\n") < 0 || ferror(f)) PFATAL("Write Hive metrics");
  if (fclose(f) || rename(temporary, destination)) PFATAL("Publish Hive metrics");
  if (hive_events && fflush(hive_events)) PFATAL("Flush Hive decision events");
}

static void hive_decision_event(uint32_t trace, uint32_t selected_count, uint64_t local_count,
                                uint64_t selected_observations, uint64_t selected_paths,
                                uint64_t threshold, uint64_t local_threshold,
                                uint32_t candidate_energy, uint32_t local_policy_energy,
                                uint32_t assigned_energy) {
  /* First 1000 scored parents, then every 1000th. Counters cover every decision.
     This systematic sample is diagnostic, not a representative random sample. */
  if (hive_frequency_decisions > 1000 && hive_frequency_decisions % 1000) return;
  if (!hive_events) {
    char path[4096];
    if (snprintf(path, sizeof path, "%s/energy_decisions.jsonl", out_dir) >= sizeof path)
      FATAL("Hive event output path too long");
    hive_events = fopen(path, "w");
    if (!hive_events) PFATAL("Open Hive decision events");
  }
  fprintf(hive_events, "{\"schema_version\":11,\"monotonic_ns\":%" PRIu64
          ",\"decision_index\":%" PRIu64 ",\"trace_hash\":%u,\"frequency_mode\":\"%s\""
          ",\"selected_frequency_count\":%u,\"local_trace_count\":%" PRIu64
          ",\"selected_observations\":%" PRIu64 ",\"selected_trace_buckets\":%" PRIu64
          ",\"local_observations\":%" PRIu64 ",\"local_trace_hashes\":%" PRIu64
          ",\"threshold\":%" PRIu64 ",\"local_threshold\":%" PRIu64
          ",\"candidate_energy\":%u,\"local_policy_energy\":%u"
          ",\"assigned_energy\":%u,\"selected_downweighted\":%s"
          ",\"local_would_downweight\":%s}\n",
          hive_now_ns(), hive_frequency_decisions, trace, hive_shared_enabled ? "global" : "local",
          selected_count, local_count, selected_observations, selected_paths,
          hive_frequency_observations, (uint64_t)hive_used, threshold, local_threshold,
          candidate_energy, local_policy_energy, assigned_energy,
          selected_count > threshold ? "true" : "false",
          local_count > local_threshold ? "true" : "false");
  ++hive_event_rows;
}
/* Fixed tools, worker-local inputs and outputs; no shell expansion. */
#ifndef HIVE_PREPROCESS_SCRIPT
#define HIVE_PREPROCESS_SCRIPT "/opt/race_predictor/fuzz_preprocess.py"
#endif
#ifndef HIVE_PAIR_SCRIPT
#define HIVE_PAIR_SCRIPT "/opt/period-wip/all_event_pairs.py"
#endif
#ifndef HIVE_PREDICTOR_JAR
#define HIVE_PREDICTOR_JAR "/opt/race_predictor/rapid.jar"
#endif
#define HIVE_PREDICTOR_CP HIVE_PREDICTOR_JAR ":/opt/race_predictor/lib/*"
extern int read_rf_set_checked(const char *, uint64_t *, uint64_t *);

static void hive_preprocess_failed(void) {
  ++hive_preprocess_failures;
  hive_last_publish = 0;
  hive_publish(0);
}
static void hive_preprocess_cleanup(void) {
  ++hive_preprocess_runs;
  const char *files[] = {"events.log","mapping.log","comb.log","event_pairs.json","all_pairs.json"};
  for (size_t i=0; i<sizeof files/sizeof files[0]; ++i) {
    if (unlink(files[i]) && errno != ENOENT) {
      hive_preprocess_failed(); PFATAL("Remove stale preprocessing file %s",files[i]);
    }
  }
}
static int hive_preprocess_command(const char *label, char *const args[]) {
  pid_t child=fork();
  if (child<0) { hive_preprocess_failed(); PFATAL("Fork preprocessing command %s",label); }
  if (!child) {
    /* Only the tool child drops preload. The fuzzer's environment is unchanged. */
    unsetenv("LD_PRELOAD");
    execvp(args[0],args);
    perror(args[0]); _exit(127);
  }
  int status;
  pid_t waited;
  do { waited=waitpid(child,&status,0); } while (waited<0 && errno==EINTR);
  if (stop_soon) return 0;
  if (waited<0) { hive_preprocess_failed(); PFATAL("Wait for preprocessing command %s",label); }
  if (!WIFEXITED(status) || WEXITSTATUS(status)!=0) {
    hive_preprocess_failed();
    FATAL("Preprocessing command %s failed (wait status %d)",label,status);
  }
  return 1;
}
static int hive_preprocess_pairs(void) {
  const char *required[]={HIVE_PREPROCESS_SCRIPT,HIVE_PREDICTOR_JAR,HIVE_PAIR_SCRIPT};
  for (unsigned i=0; i<(ALL_PAIRS ? 3U : 2U); ++i) {
    if (access(required[i],R_OK)) {
      hive_preprocess_failed(); PFATAL("Missing preprocessing tool %s",required[i]);
    }
  }
  char *preprocess[]={"python3",HIVE_PREPROCESS_SCRIPT,"events.log","mapping.log","comb.log",NULL};
  if (!hive_preprocess_command("trace conversion",preprocess)) return 0;
  if (ALL_PAIRS) {
    char *pairs[]={"python3",HIVE_PAIR_SCRIPT,NULL};
    if (!hive_preprocess_command("pair generation",pairs)) return 0;
  }
  char *predict[]={"java","-cp",HIVE_PREDICTOR_CP,"Main","-t","comb.log","-s","event_pairs.json",
                   "-sp",SP,"-dp",DP,"-w","true",NULL};
  return hive_preprocess_command("race prediction",predict);
}
static int hive_load_pairs(const char *file) {
  uint64_t loaded=0,available=0;
  int result=read_rf_set_checked(file,&loaded,&available);
  if (result<0) { hive_preprocess_failed(); FATAL("Failed to load RF pair file %s",file); }
  ++hive_pair_loads;
  if (!loaded) ++hive_pair_empty_loads;
  hive_pair_last_count=loaded; hive_pair_available=available;
  SAYF("[+] RF pair load: %s, records=%" PRIu64 ", cumulative=%" PRIu64 "%s\n",
       file,loaded,available,loaded ? "" : " (valid empty set)");
  return result==1;
}
static void hive_mutation_observe(const struct sched_entry *parent, const struct sched_entry *child) {
  const Sched *b=child->sched;
  if (b->pos_len+b->neg_len) ++hive_mutation_with_obligations;
  if (!parent) { ++hive_mutation_initial; return; }
  const Sched *a=parent->sched;
  int changed=a->pos_len!=b->pos_len || a->neg_len!=b->neg_len;
  if (!changed) for (size_t i=0; i<a->pos_len+a->neg_len; ++i) {
    if (a->obligations[i].r!=b->obligations[i].r || a->obligations[i].w!=b->obligations[i].w) {
      changed=1; break;
    }
  }
  int seed=a->random_seed!=b->random_seed;
  int flags=a->delay!=b->delay || a->dist!=b->dist || a->avoid_uninit_writes!=b->avoid_uninit_writes;
  hive_mutation_obligations += changed; hive_mutation_seed += seed; hive_mutation_flags += flags;
  hive_mutation_unchanged += !changed && !seed && !flags;
}

#endif
