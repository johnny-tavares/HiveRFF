#define main afl_program_main
#include "afl-fuzz.c"
#undef main
#include <assert.h>

int main(int argc, char **argv) {
  assert(argc>=3); out_dir=(u8 *)argv[2];
  if (!strcmp(argv[1],"checked")) {
    for (int i=3;i<argc;++i) {
      uint64_t loaded=999,available=999;
      int result=read_rf_set_checked(argv[i],&loaded,&available);
      printf("LOAD %d %" PRIu64 " %" PRIu64 "\n",result,loaded,available);
    }
  } else if (!strcmp(argv[1],"load")) {
    assert(argc==4); hive_load_pairs(argv[3]); hive_publish(1);
  } else if (!strcmp(argv[1],"pipeline")) {
    assert(argc==3); SP="min; touch UNEXPECTED"; DP="absSum";
    setenv("LD_PRELOAD","parent-preload-sentinel",1);
    hive_preprocess_cleanup();
    FILE *f=fopen("events.log","w");assert(f);fputs("fixture",f);fclose(f);
    f=fopen("mapping.log","w");assert(f);fclose(f);
    assert(hive_preprocess_pairs());
    assert(!strcmp(getenv("LD_PRELOAD"),"parent-preload-sentinel"));
    unsetenv("LD_PRELOAD");
    assert(hive_load_pairs("all_pairs.json"));
    assert(hive_pair_last_count==1 && hive_pair_available==1);
    assert(access("UNEXPECTED",F_OK));
    hive_publish(1);
  } else if (!strcmp(argv[1],"mutate")) {
    assert(argc==4);hive_load_pairs(argv[3]);init_prng(1234);
    struct sched_entry parent={0};parent.sched=empty_sched();
    struct sched_entry initial={0};initial.sched=parent.sched;
    hive_mutation_observe(NULL,&initial);
    for (int i=0;i<200;++i) {
      struct sched_entry child={0}; child.sched=mutate(parent.sched);
      hive_mutation_observe(&parent,&child);
      free(child.sched);
    }
    assert(hive_mutation_obligations>0 && hive_mutation_seed>0);
    assert(hive_mutation_with_obligations==hive_mutation_obligations);
    hive_publish(1);
  } else if (!strcmp(argv[1],"command")) {
    assert(argc>=4); hive_preprocess_command("test command",argv+3);
  } else assert(0);
  return 0;
}
