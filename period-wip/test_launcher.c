/* Link wrappers inspect real manager launch arguments without starting AFL or touching /opt. */
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
int __wrap_system(const char *command) { (void)command; return 0; }
int __wrap_chdir(const char *path) { (void)path; return 0; }
int __wrap_execv(const char *path, char *const args[]) {
  assert(!strcmp(path, "/opt/sched-fuzz/AFL-2.57b/afl-fuzz"));
  int seed = atoi(getenv("SEED")); assert(seed >= 401 && seed <= 402);
  int sync = !strcmp(getenv("HIVE_AFL_SYNC"), "on"), saw_sync = 0, saw_output = 0, saw_skip = 0;
  int shared = !strcmp(getenv("HIVE_FREQUENCY_MODE"), "global") || !strcmp(getenv("HIVE_NOVELTY_MODE"), "shared");
  assert(!!getenv("HIVEMIND_SHM") == shared);
  char output[128]; snprintf(output, sizeof output, "/tmp/test-output/worker_%d", seed - 401);
  for (int i = 0; args[i]; ++i) {
    if (!strcmp(args[i], "-S")) saw_sync = 1;
    if (!strcmp(args[i], "-d")) ++saw_skip;
    if (!strcmp(args[i], "-o")) { saw_output = 1; assert(!strcmp(args[i+1], sync ? "/tmp/test-output" : output)); }
  }
  assert(saw_output && saw_sync == sync);
  assert(saw_skip == !sync); /* Exactly one -d without sync; never -S plus -d. */
  _exit(0);
}
