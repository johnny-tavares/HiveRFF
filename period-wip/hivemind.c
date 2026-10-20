#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <sys/shm.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <unistd.h>
#include <sys/wait.h>
#include <signal.h>
#include <errno.h>
#include <limits.h>

static void request_stop(int signal_number) { (void)signal_number; }

#define SHM_SIZE (50 * 1024 * 1024)

static const char *mode(const char *key, const char *fallback, const char *a, const char *b) {
    const char *value = getenv(key);
    if (!value) value = fallback;
    if (strcmp(value, a) && strcmp(value, b)) {
        fprintf(stderr, "Invalid %s: %s\n", key, value);
        exit(1);
    }
    setenv(key, value, 1);
    return getenv(key);
}

static long number(const char *key, long fallback, long minimum) {
    const char *value = getenv(key);
    if (!value) return fallback;
    char *end;
    errno = 0;
    long result = strtol(value, &end, 10);
    if (errno || !*value || *end || result < minimum || result > INT_MAX) {
        fprintf(stderr, "Invalid %s\n", key);
        exit(1);
    }
    return result;
}

int main() {
    printf("[*] Hive Mind Manager starting...\n");

    const char *frequency = mode("HIVE_FREQUENCY_MODE", "global", "global", "local");
    const char *novelty = mode("HIVE_NOVELTY_MODE", "shared", "shared", "local");
    const char *sync_mode = mode("HIVE_AFL_SYNC", "on", "on", "off");
    int workers = (int)number("WORKERS", 16, 1);
    long seed_base = number("HIVE_SEED_BASE", 100, 0);
    if (seed_base > INT_MAX - workers) { fprintf(stderr, "Worker seed overflow\n"); return 1; }
    int use_shared = !strcmp(frequency, "global") || !strcmp(novelty, "shared");
    char shm_name[64];
    /* Reuse the legacy segment: allocating a second 50 MB block can exhaust
       Docker's default /dev/shm in an already-open container. The runner lock
       and fixed worker scratch directories require one manager at a time. */
    snprintf(shm_name, sizeof shm_name, "/hivemind_shm");
    void *base_addr = NULL;
    if (use_shared) {
        int shm_fd = shm_open(shm_name, O_CREAT | O_RDWR, 0600);
        if (shm_fd == -1) { perror("shm_open"); return 1; }
        if (ftruncate(shm_fd, SHM_SIZE)) { perror("ftruncate"); shm_unlink(shm_name); return 1; }
        base_addr = mmap(0, SHM_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, shm_fd, 0);
        close(shm_fd);
        if (base_addr == MAP_FAILED) { perror("mmap"); shm_unlink(shm_name); return 1; }
        memset(base_addr, 0, SHM_SIZE);
        memset(base_addr, 255, 65536 + 32768);
    }
    printf("[*] frequency=%s novelty=%s afl_sync=%s seed_base=%ld\n",
           frequency, novelty, sync_mode, seed_base);

    const char* target_binary = getenv("TARGET_PROG");
    if (target_binary == NULL) {
        fprintf(stderr, "[-] FATAL: TARGET_PROG environment variable not set.\n");
        exit(1);
    }

    const char *output_dir = getenv("HIVE_OUTPUT_DIR");
    if (output_dir == NULL) output_dir = "/opt/out";

    pid_t pids[workers];
    fflush(NULL);

    for (int i = 0; i < workers; i++) {
        pids[i] = fork();
        if (pids[i] < 0) {
            perror("fork");
            for (int j = 0; j < i; ++j) kill(pids[j], SIGTERM);
            for (int j = 0; j < i; ++j) waitpid(pids[j], NULL, 0);
            if (use_shared) shm_unlink(shm_name);
            return 1;
        }
        if (pids[i] == 0) {
            char worker_cwd[64];
            sprintf(worker_cwd, "/opt/sched-fuzz_worker_%d", i);

            char setup_cmd[2048];
            sprintf(setup_cmd, "rm -rf %s && mkdir -p %s && ln -s /opt/sched-fuzz/afl-in %s/afl-in", 
                    worker_cwd, worker_cwd, worker_cwd);
            system(setup_cmd);

            char sym_cmd[2048];
            sprintf(sym_cmd, "ln -s /opt/sched-fuzz/out.csv %s/out.csv && "
                             "ln -s /opt/sched-fuzz/events.log %s/events.log && "
                             "ln -s /opt/sched-fuzz/mapping.log %s/mapping.log && "
                             "ln -s /opt/sched-fuzz/comb.log %s/comb.log && "
                             "ln -s /opt/sched-fuzz/event_pairs.json %s/event_pairs.json && "
                             "ln -s /opt/sched-fuzz/all_pairs.json %s/all_pairs.json",
                    worker_cwd, worker_cwd, worker_cwd, worker_cwd, worker_cwd, worker_cwd);
            system(sym_cmd);

            chdir(worker_cwd);

            setenv("AFL_PRELOAD", "/opt/sched-fuzz/libsched.so", 1);
	    setenv("SCHEDULE", "./SCHEDULE", 1);
            if (use_shared) setenv("HIVEMIND_SHM", shm_name, 1);
            else unsetenv("HIVEMIND_SHM");
            
            char seed_val[16];
	    long trial_offset = seed_base;
            sprintf(seed_val, "%ld", i + 1 + trial_offset);
            setenv("SEED", seed_val, 1);

            char sync_id[32];
            sprintf(sync_id, "worker_%d", i);

            printf("[Worker %d] Launching AFL against: %s (CWD: %s)\n", i, target_binary, worker_cwd);
            
            // Preserve worker_N output layout in both synchronized and independent modes.
            char worker_output[4096];
            if (snprintf(worker_output, sizeof worker_output, "%s/%s", output_dir, sync_id) >= (int)sizeof worker_output) {
                fprintf(stderr, "Worker output path too long\n"); exit(1);
            }
            char *args[20];
            int n = 0;
            args[n++] = "afl-fuzz";
            args[n++] = "-m"; args[n++] = "none";
            args[n++] = "-i"; args[n++] = "afl-in";
            args[n++] = "-o";
            args[n++] = !strcmp(sync_mode, "on") ? (char *)output_dir : worker_output;
            args[n++] = "-t"; args[n++] = "8000+";
            /* -S implies -d. Keep independent workers on the same schedule
               fuzzing path; AFL rejects combining explicit -d with -S. */
            if (!strcmp(sync_mode, "on")) { args[n++] = "-S"; args[n++] = sync_id; }
            else { args[n++] = "-d"; }
            args[n++] = "--"; args[n++] = (char *)target_binary; args[n] = NULL;
            execv("/opt/sched-fuzz/AFL-2.57b/afl-fuzz", args);

            perror("execl failed");
            exit(1);
        }
    }

    /* Children retain the default disposition; only the manager waits through shutdown. */
    signal(SIGTERM, request_stop);
    signal(SIGINT, request_stop);
    int failed = 0;
    for (int i = 0; i < workers; i++) {
        int status;
        pid_t result;
        do { result = waitpid(pids[i], &status, 0); } while (result < 0 && errno == EINTR);
        if (result < 0 || !WIFEXITED(status) || WEXITSTATUS(status) != 0) failed = 1;
    }

    if (use_shared) { munmap(base_addr, SHM_SIZE); shm_unlink(shm_name); }
    printf("[*] Hive Mind shut down gracefully.\n");
    return failed;
}
