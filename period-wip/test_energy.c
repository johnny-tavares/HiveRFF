#define main afl_program_main
#include "afl-fuzz.c"
#undef main
#include <assert.h>
static u32 test_frequency, test_paths;
static uint64_t test_observations;
u32 get_path_id_count(u32 id) { (void)id; return test_frequency; }
u32 total_paths(void) { return test_paths; }
uint64_t total_path_observations(void) { return test_observations; }

static struct sched_entry parent(void) {
  struct sched_entry q = {0};
  q.exec_us=100; q.set_bits=100; q.sched_trace_id=42; q.fuzz_level=8;
  skip=0; adj=1;
  return q;
}

int main(int argc, char **argv) {
  assert(argc == 2); out_dir=(u8 *)argv[1]; POWER_COE=1;
  stage_max=100; stage_cur=0; sched_nondets=1;
  total_sched_exec_us=200; total_sched_set_bits=200;
  /* 1000 local normal executions / 10 traces = mean 100; adjustment = 1. */
  for (int trace=42; trace<52; ++trace) for (int i=0; i<100; ++i) hive_observe(trace);
  assert(hive_frequency_observations==1000 && hive_used==10 && hive_local_count(42)==100);
  test_observations=1000; test_paths=10; test_frequency=100;
  struct sched_entry q=parent();
  u32 local=calculate_sched_score(&q);
  assert(local==100 && q.fuzz_level==9 && skip==0 && adj==1);
  /* AFL calibration/replay counts must have no effect on the policy. */
  total_execs=UINT64_MAX;
  q=parent(); assert(calculate_sched_score(&q)==local);
  /* Duplicating the worker population preserves both acceptance and batch energy. */
  hive_shared_enabled=1;
  for (int workers=1; workers<=64; ++workers) {
    test_observations=1000*workers; test_frequency=100*workers;
    q=parent(); assert(calculate_sched_score(&q)==local);
  }
  /* A globally hot trace is rejected even when the local policy accepts it. */
  test_observations=16000; test_paths=10; test_frequency=2000;
  uint64_t prior=hive_shared_reject_local_policy_pass;
  q=parent(); assert(calculate_sched_score(&q)==0);
  assert(hive_shared_reject_local_policy_pass==prior+1 && adj==2);
  /* Regression: at global u=51, local frequency=100 fails SAME threshold,
     but passes its OWN threshold=101. The old diagnostic missed this. */
  test_observations=16000; test_paths=320; test_frequency=100;
  prior=hive_shared_reject_local_policy_pass;
  uint64_t same=hive_shared_only;
  q=parent(); assert(calculate_sched_score(&q)==0);
  assert(hive_shared_reject_local_policy_pass==prior+1 && hive_shared_only==same);
  /* Reverse disagreement: this worker oversampled a globally ordinary trace. */
  for (int i=0; i<100; ++i) hive_observe(42);
  test_observations=16000; test_paths=10; test_frequency=1600;
  prior=hive_shared_pass_local_policy_reject;
  q=parent(); assert(calculate_sched_score(&q)>0);
  assert(hive_shared_pass_local_policy_reject==prior+1);
  /* One-worker global and local agree with identical population and history. */
  test_observations=hive_frequency_observations; test_paths=hive_used;
  for (int level=0; level<=31; ++level) {
    for (int trace=42; trace<52; ++trace) {
      struct sched_entry a=parent(); a.fuzz_level=level; a.sched_trace_id=trace;
      test_frequency=hive_local_count(trace); hive_shared_enabled=0;
      u32 expected=calculate_sched_score(&a); uint64_t expected_adj=adj;
      struct sched_entry b=parent(); b.fuzz_level=level; b.sched_trace_id=trace;
      hive_shared_enabled=1;
      assert(calculate_sched_score(&b)==expected);
      assert(b.fuzz_level==a.fuzz_level && adj==expected_adj);
    }
  }
  assert(hive_threshold(0,0,0)==1);
  assert(hive_threshold(UINT64_MAX,1,1)==UINT64_MAX);
  assert(hive_threshold(1000,10,1)==101);
  assert(hive_energy(31,1,UINT32_MAX,100)==100); /* no u32 multiplication wrap */
  assert(hive_energy(0,100,100,100)==0);
  test_frequency=UINT32_MAX; test_paths=1; test_observations=1;
  q=parent(); adj=UINT64_MAX;
  assert(calculate_sched_score(&q)==0 && adj==UINT64_MAX);
  assert(hive_rejected==hive_shared_only+hive_also_local);
  /* The diagnostic sample includes periodic events after the first 1000. */
  test_frequency=100; test_observations=1000; test_paths=10;
  while(hive_frequency_decisions<2000) { q=parent(); calculate_sched_score(&q); }
  assert(hive_event_rows==1001);
  hive_publish(1);
  return 0;
}
