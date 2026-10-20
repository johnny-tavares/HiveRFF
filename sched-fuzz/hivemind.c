#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <sys/shm.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <unistd.h>
#include <sys/wait.h>

#define SHM_SIZE (50 * 1024 * 1024)

int main() {
    printf("[*] Hive Mind Manager starting...\n");

    int shm_fd = shm_open("/hivemind_shm", O_CREAT | O_RDWR, 0666);
    if (shm_fd == -1) { perror("shm_open"); exit(1); }

    ftruncate(shm_fd, SHM_SIZE);
    
    void *base_addr = mmap(0, SHM_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, shm_fd, 0);
    if (base_addr == MAP_FAILED) { perror("mmap"); exit(1); }

    memset(base_addr, 0, SHM_SIZE);
    memset(base_addr, 255, 65536 + 32768);

    const char* workers_str = getenv("WORKERS");
    if (workers_str == NULL) { exit(1); }
    int workers = atoi(workers_str);

    // Capture the original execution directory
    char orig_cwd[1024];
    if (getcwd(orig_cwd, sizeof(orig_cwd)) == NULL) {
        perror("getcwd failed");
        exit(1);
    }

    for(int i = 0; i < workers; i++) {
        pid_t pid = fork();
        
        if (pid == 0) { 
            const char *target_binary = getenv("HIVEMIND_TARGET");
            if (target_binary == NULL) { exit(1); }

            // 1. Create a Sibling Sandbox to preserve relative paths like ../race_predictor
            char worker_cwd[1024];
            sprintf(worker_cwd, "%s_worker_%d", orig_cwd, i);
            mkdir(worker_cwd, 0777);

            // 2. Clone the environment using symlinks so AFL-2.57b and libsched.so are accessible
            char sym_cmd[2048];
            sprintf(sym_cmd, "for f in %s/*; do ln -s \"$f\" %s/ 2>/dev/null; done", orig_cwd, worker_cwd);
            system(sym_cmd);

            // 3. Break symlinks for the specific files that cause the Swarm Collision
            sprintf(sym_cmd, "rm -f %s/events.log %s/mapping.log %s/comb.log %s/event_pairs.json %s/all_pairs.json %s/SCHEDULE",
                    worker_cwd, worker_cwd, worker_cwd, worker_cwd, worker_cwd, worker_cwd);
            system(sym_cmd);

            // 4. Enter the sandbox
            chdir(worker_cwd);

            // 5. Safely set isolated environment variables
            setenv("AFL_PRELOAD", "./libsched.so", 1);
            setenv("SCHEDULE", "./SCHEDULE", 1);
            setenv("HIVEMIND_SHM", "/hivemind_shm", 1);
            
            char seed_val[16];
            sprintf(seed_val, "%d", i + 1);
            setenv("SEED", seed_val, 1);

            char sync_id[32];
            sprintf(sync_id, "worker_%d", i);

            printf("[Worker %d] Launching AFL against: %s (CWD: %s)\n", i, target_binary, worker_cwd);
            
            // Launch using the symlinked path inside the sandbox
            execl("./AFL-2.57b/afl-fuzz", "afl-fuzz", 
                  "-m", "none", "-i", "afl-in", "-o", "/opt/out", 
                  "-t", "5000+", 
                  "-S", sync_id, "--", target_binary, 
                  "-c", "-k", "-f", "-p4", "-1", "-b1", "@@", NULL);
          
            perror("execl failed");
            exit(1);
        }
    }

    for(int i = 0; i < workers; i++){
        wait(NULL);
    }

    shm_unlink("/hivemind_shm");
    printf("[*] Hive Mind shut down gracefully.\n");

    return 0;
}
