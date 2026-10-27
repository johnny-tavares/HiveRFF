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
  return q;
}

int main(int argc, char **argv) {
  assert(argc == 2); out_dir=(u8 *)argv[1]; POWER_COE=1;
  stage_max=100; stage_cur=0; sched_nondets=1;
  total_sched_exec_us=200; total_sched_set_bits=200;
  /* 1000 local normal executions / 10 traces = mean 100. */
  for (int trace=42; trace<52; ++trace) for (int i=0; i<100; ++i) hive_observe(trace);
  assert(hive_frequency_observations==1000 && hive_used==10 && hive_local_count(42)==100);
  test_observations=1000; test_paths=10; test_frequency=100;
  struct sched_entry q=parent();
  u32 local=calculate_sched_score(&q);
  assert(local==100 && q.fuzz_level==9);
  /* AFL calibration/replay counts must have no effect on the policy. */
  total_execs=UINT64_MAX;
  q=parent(); assert(calculate_sched_score(&q)==local);
  /* Duplicating the worker population preserves both acceptance and batch energy. */
  hive_shared_enabled=1;
  for (int workers=1; workers<=64; ++workers) {
    test_observations=1000*workers; test_frequency=100*workers;
    q=parent(); assert(calculate_sched_score(&q)==local);
  }
  /* A globally hot trace receives three parts full plus one part proportional energy. */
  test_observations=16000; test_paths=10; test_frequency=2000;
  uint64_t prior=hive_shared_downweight_local_full;
  q=parent(); assert(calculate_sched_score(&q)==95);
  assert(hive_shared_downweight_local_full==prior+1 && q.fuzz_level==9);
  /* Population normalization matters: global mean 50 downweights the selected
     count while the worker-local mean 100 still grants full energy. */
  test_observations=16000; test_paths=320; test_frequency=100;
  prior=hive_shared_downweight_local_full;
  q=parent(); assert(calculate_sched_score(&q)==88);
  assert(hive_shared_downweight_local_full==prior+1);
  /* Reverse disagreement: this worker oversampled a globally ordinary trace. */
  for (int i=0; i<100; ++i) hive_observe(42);
  test_observations=16000; test_paths=10; test_frequency=1600;
  prior=hive_shared_full_local_downweight;
  q=parent(); assert(calculate_sched_score(&q)==100);
  assert(hive_shared_full_local_downweight==prior+1);
  /* One-worker global and local agree with identical population and history. */
  test_observations=hive_frequency_observations; test_paths=hive_used;
  for (int level=0; level<=31; ++level) {
    for (int trace=42; trace<52; ++trace) {
      struct sched_entry a=parent(); a.fuzz_level=level; a.sched_trace_id=trace;
      test_frequency=hive_local_count(trace); hive_shared_enabled=0;
      u32 expected=calculate_sched_score(&a);
      struct sched_entry b=parent(); b.fuzz_level=level; b.sched_trace_id=trace;
      hive_shared_enabled=1;
      assert(calculate_sched_score(&b)==expected);
      assert(b.fuzz_level==a.fuzz_level);
    }
  }
  assert(hive_threshold(0,0,0)==1);
  assert(hive_threshold(UINT64_MAX,1,1)==UINT64_MAX);
  assert(hive_threshold(1000,10,1)==101);
  assert(hive_energy(31,1,UINT32_MAX,100)==100); /* no u32 multiplication wrap */
  assert(hive_energy(0,100,100,100)==0);
  assert(hive_frequency_energy(100,100,100)==100);
  assert(hive_frequency_energy(100,200,100)==88);
  assert(hive_frequency_energy(100,201,100)==88); /* rounds up */
  assert(hive_frequency_energy(100,UINT64_MAX,1)==76); /* no overflow, > 75% */
  assert(hive_frequency_energy(100,UINT64_MAX,0)==75);
  assert(hive_frequency_energy(0,UINT64_MAX,1)==0);
  assert(hive_frequency_energy(1,UINT64_MAX,1)==1);
  assert(hive_frequency_energy(UINT32_MAX,UINT64_MAX,UINT64_MAX-1)==UINT32_MAX);
  /* Bounds and monotonicity across small rounded and maximum-size budgets. */
  const uint32_t candidates[] = {1, 2, 3, 4, 7, 100, UINT32_MAX};
  const uint64_t counts[] = {0, 1, 100, 101, 200, 201, UINT32_MAX, UINT64_MAX};
  for (size_t c=0; c<sizeof candidates/sizeof candidates[0]; ++c) {
    uint32_t previous=candidates[c];
    for (size_t i=0; i<sizeof counts/sizeof counts[0]; ++i) {
      uint32_t assigned=hive_frequency_energy(candidates[c],counts[i],100);
      assert(assigned<=previous && assigned<=candidates[c]);
      assert((uint64_t)4*assigned >= (uint64_t)3*candidates[c]);
      previous=assigned;
    }
  }
  test_frequency=UINT32_MAX; test_paths=1; test_observations=1;
  q=parent(); assert(calculate_sched_score(&q)==76);
  q=parent(); q.fuzz_level=0;
  assert(calculate_sched_score(&q)==0 && q.fuzz_level==1);
  assert(hive_downweighted+hive_full_energy+hive_zero_other==hive_frequency_decisions);
  /* The diagnostic sample includes periodic events after the first 1000. */
  test_frequency=100; test_observations=1000; test_paths=10;
  while(hive_frequency_decisions<2000) { q=parent(); calculate_sched_score(&q); }
  assert(hive_event_rows==1001);
  hive_publish(1);
  return 0;
}
