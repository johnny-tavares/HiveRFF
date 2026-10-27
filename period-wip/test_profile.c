#define main afl_program_main
#include "afl-fuzz.c"
#undef main
#include <assert.h>
u32 total_paths(void) { return 1; }
uint64_t total_path_observations(void) { return 0; }
int main(int argc, char **argv) {
  assert(argc==2); out_dir=(u8 *)argv[1];
  unsetenv("HIVE_PROFILE"); hive_profile_configure();
  assert(!hive_profile_enabled);
  hive_profile_row("selection",NULL,NULL,0,0,0);
  assert(!hive_profile_file);
  setenv("HIVE_PROFILE","1",1); hive_profile_configure();
  ReadFrom a[]={{123,456},{789,1011}}, b[]={{123,456},{789,1011}};
  Sched x,y;
  memset(&x,0xAA,sizeof x); memset(&y,0x55,sizeof y);
  x.random_seed=y.random_seed=7; x.delay=y.delay=2; x.dist=y.dist=1;
  x.avoid_uninit_writes=y.avoid_uninit_writes=true;
  x.pos_len=y.pos_len=1; x.neg_len=y.neg_len=1;
  x.obligations=a; y.obligations=b;
  assert(hive_profile_schedule(&x,1)==hive_profile_schedule(&y,1));
  y.random_seed=8;
  assert(hive_profile_schedule(&x,1)!=hive_profile_schedule(&y,1));
  assert(hive_profile_schedule(&x,0)==hive_profile_schedule(&y,0));
  b[1].w++;
  assert(hive_profile_schedule(&x,0)!=hive_profile_schedule(&y,0));
  assert(hive_profile_schedule(NULL,1)!=hive_profile_schedule(&x,1));
  assert(hive_profile_input((u8 *)"a",1)!=hive_profile_input((u8 *)"b",1));
  struct sched_entry parent={0},child={0};parent.sched=&x;child.sched=&y;
  trace_bits=calloc(1,MAP_SIZE+SCHED_MAP_SIZE);assert(trace_bits);
  uint64_t begin=HIVE_PROFILE_START();
  HIVE_PROFILE_END(selection,begin);
  hive_profile_row("selection",&parent,NULL,123,88,0);
  hive_profile_row("execution",&parent,&child,123,0,0);
  hive_profile_rows=HIVE_PROFILE_LIMIT;
  hive_profile_row("execution",&parent,&child,123,0,0);
  assert(hive_profile_dropped==1); hive_profile_rows=2;
  hive_publish(1);
  return 0;
}
