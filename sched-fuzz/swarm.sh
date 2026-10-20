#!/bin/bash

# 1. Ensure the user provided a target
if [ -z "$1" ]; then
  echo -e "\033[31mUsage:\033[0m $0 <path_to_target_binary>"
  exit 1
fi

TARGET_PROG="$1"
WORKERS="$2"
TIME_BUDGET="$3"
# 2. Run the instrumentation script
echo "[*] Instrumenting target: $TARGET_PROG"
./instrument.sh "$TARGET_PROG"

# Stop if instrumentation fails
if [ $? -ne 0 ]; then
  echo -e "\033[31m[-] Instrumentation failed! Aborting.\033[0m"
  exit 1
fi

# 3. Export the target to the environment and launch Hive Mind
echo "[*] Instrumentation complete. Waking the Hive Mind..."

export HIVEMIND_TARGET="$TARGET_PROG"
export WORKERS="$WORKERS"
export FUZZERS=power-coe-schedfuzz
export NUM_TRIALS=1
export TIME_BUDGET="$TIME_BUDGET"
./hivemind
