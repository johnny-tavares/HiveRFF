#define main afl_program_main
#include "afl-fuzz.c"
#undef main
#include <assert.h>

int main(int argc, char **argv) {
  assert(argc == 4);
  int shared_frequency = !strcmp(argv[1], "global");
  int shared_novelty = !strcmp(argv[2], "shared");
  char name[64]; snprintf(name, sizeof name, "/hive_test_%ld", (long)getpid());
  int fd = shm_open(name, O_CREAT | O_EXCL | O_RDWR, 0600); assert(fd >= 0);
  assert(!ftruncate(fd, 50 * 1024 * 1024));
  u8 *base = mmap(NULL, 50 * 1024 * 1024, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
  assert(base != MAP_FAILED); close(fd);
  memset(base, 255, MAP_SIZE + SCHED_MAP_SIZE);
  base[123] = 17; /* Existing discovery must survive worker startup. */
  setenv("HIVEMIND_SHM", name, 1);
  setenv("HIVE_FREQUENCY_MODE", argv[1], 1); setenv("HIVE_NOVELTY_MODE", argv[2], 1);
  configure_hive_sharing();
  shm_unlink(name);
  assert(hive_shared_enabled == shared_frequency && hive_novelty_shared == shared_novelty);
  setup_shm();
  assert(virgin_bits[123] == (shared_novelty ? 17 : 255));
  store_path_id(42); assert(total_path_observations() == 1); assert(get_path_id_count(42) == 1 && total_paths() == 1);
  pid_t child = fork(); assert(child >= 0);
  if (!child) {
    store_path_id(42); store_path_id(43);
    virgin_bits[123] = 9;
    _exit(0);
  }
  int status; assert(waitpid(child, &status, 0) == child && WIFEXITED(status) && !WEXITSTATUS(status));
  assert(get_path_id_count(42) == (shared_frequency ? 2 : 1));
  assert(total_paths() == (shared_frequency ? 2 : 1));
  assert(virgin_bits[123] == (shared_novelty ? 9 : 255));
  assert(total_path_observations() == (shared_frequency ? 3 : 1));
  /* Concurrent increments preserve the total and bucket counts across processes. */
  pid_t children[4];
  for (int i=0;i<4;++i) {
    children[i]=fork(); assert(children[i]>=0);
    if (!children[i]) { for(int j=0;j<10000;++j) store_path_id(42); _exit(0); }
  }
  for (int i=0;i<4;++i) {
    assert(waitpid(children[i], &status, 0)==children[i]);
    assert(WIFEXITED(status) && !WEXITSTATUS(status));
  }
  assert(total_path_observations() == (shared_frequency ? 40003 : 1));
  assert(get_path_id_count(42) == (shared_frequency ? 40002 : 1));
  assert(total_paths() == (shared_frequency ? 2 : 1));
  out_dir = (u8 *)argv[3]; hive_publish(1);
  return 0;
}
