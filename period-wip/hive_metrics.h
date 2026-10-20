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
static uint64_t hive_exec_ns, hive_decisions, hive_rejected, hive_shared_only;
static uint64_t hive_frequency_observations, hive_frequency_decisions;
static uint64_t hive_shared_reject_local_policy_pass, hive_shared_pass_local_policy_reject;
static uint64_t hive_also_local, hive_zero_other, hive_candidate_budget;
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

static uint64_t hive_now_ns(void) {
  struct timespec t;
  if (clock_gettime(CLOCK_MONOTONIC, &t)) PFATAL("clock_gettime");
  return (uint64_t)t.tv_sec * 1000000000ULL + t.tv_nsec;
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
  char temporary[4096], destination[4096];
  if (snprintf(temporary, sizeof temporary, "%s/hive_metrics.json.tmp", out_dir) >= sizeof temporary ||
      snprintf(destination, sizeof destination, "%s/hive_metrics.json", out_dir) >= sizeof destination)
    FATAL("Hive metrics output path too long");
  FILE *f = fopen(temporary, "w");
  if (!f) PFATAL("Open Hive metrics");
  fprintf(f, "{\"schema_version\":6,\"final\":%s,\"published_monotonic_ns\":%" PRIu64,
          final ? "true" : "false", now);
  fprintf(f, ",\"frequency_mode\":\"%s\",\"novelty_mode\":\"%s\",\"afl_sync\":\"%s\"",
          hive_shared_enabled ? "global" : "local", hive_novelty_shared ? "shared" : "local",
          sync_id ? "on" : "off");
#define HIVE_FIELD(label, value) fprintf(f, ",\"" label "\":%" PRIu64, (uint64_t)(value))
  fprintf(f, ",\"frequency_policy\":\"population_mean_v1\"");
  HIVE_FIELD("local_frequency_observations", hive_frequency_observations);
  HIVE_FIELD("selected_frequency_observations", total_path_observations());
  HIVE_FIELD("selected_frequency_trace_buckets", total_paths());
  HIVE_FIELD("frequency_decisions", hive_frequency_decisions);
  HIVE_FIELD("shared_rejections_local_policy_would_pass", hive_shared_reject_local_policy_pass);
  HIVE_FIELD("shared_passes_local_policy_would_reject", hive_shared_pass_local_policy_reject);
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
  HIVE_FIELD("frequency_rejections", hive_rejected);
  HIVE_FIELD("shared_frequency_rejections_local_would_pass", hive_shared_only);
  HIVE_FIELD("frequency_rejections_local_also_fails", hive_also_local);
  HIVE_FIELD("zero_energy_other", hive_zero_other);
  HIVE_FIELD("same_threshold_candidate_mutation_budget", hive_candidate_budget);
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
                                uint64_t threshold, uint64_t local_threshold, uint64_t adjustment,
                                int selected_pass, int local_policy_pass, uint32_t assigned_energy,
                                uint32_t same_candidate) {
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
  fprintf(hive_events, "{\"schema_version\":6,\"monotonic_ns\":%" PRIu64
          ",\"decision_index\":%" PRIu64 ",\"trace_hash\":%u,\"frequency_mode\":\"%s\""
          ",\"selected_frequency_count\":%u,\"local_trace_count\":%" PRIu64
          ",\"selected_observations\":%" PRIu64 ",\"selected_trace_buckets\":%" PRIu64
          ",\"local_observations\":%" PRIu64 ",\"local_trace_hashes\":%" PRIu64
          ",\"threshold\":%" PRIu64 ",\"local_threshold\":%" PRIu64
          ",\"adjustment\":%" PRIu64 ",\"assigned_energy\":%u"
          ",\"same_threshold_candidate_budget\":%u,\"selected_would_pass\":%s"
          ",\"local_would_pass\":%s,\"local_policy_would_pass\":%s}\n",
          hive_now_ns(), hive_frequency_decisions, trace, hive_shared_enabled ? "global" : "local",
          selected_count, local_count, selected_observations, selected_paths,
          hive_frequency_observations, (uint64_t)hive_used, threshold, local_threshold,
          adjustment, assigned_energy, same_candidate, selected_pass ? "true" : "false",
          local_count <= threshold ? "true" : "false", local_policy_pass ? "true" : "false");
  ++hive_event_rows;
}
#endif
