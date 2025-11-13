#!/bin/bash

# --- Configuration ---
HOST_ROOT="/host"
SCC_DIR="${HOST_ROOT}/opt/scc"
LOG_FILE="${SCC_DIR}/security_scans.log"
# Array of scripts to execute in order
# "/app/run_openScap.sh"
# "/app/run_STIG.sh"
SCRIPTS_TO_RUN=(    
    "/app/run_openScap.sh"
    "/app/run_STIG.sh"
)

# Counters for the final summary
SUCCESS_COUNT=0
FAILURE_COUNT=0
TOTAL_COUNT=${#SCRIPTS_TO_RUN[@]}

# --- Logging Function ---
print2log() {
    local message="$1"
    local timestamp
    timestamp=$(date +"%Y-%m-%d %H:%M:%S.%6N")
    # This mkdir -p is safe; it won't error if the dir exists
    mkdir -p "$(dirname "$LOG_FILE")"
    echo "[$timestamp] $message" | tee -a "$LOG_FILE"
}

# --- Main Logic ---

# --- Cleanup Section (Corrected) ---
# Explicitly remove all old logs, including the wrapper's log, for a clean slate.
rm -f "${SCC_DIR}/security_scans.log"
rm -f "${SCC_DIR}/stig_scan.log"
rm -f "${SCC_DIR}/output.txt"
rm -f "${SCC_DIR}/mail.log"

# Clean the openscap results directory if it exists
if [ -d "${SCC_DIR}/openscap_results" ]; then
    rm -f "${SCC_DIR}/openscap_results"/*
fi

# Now, start logging to the new, empty files
print2log "--- Old log and result files cleaned up ---"
# --- End of Cleanup Section ---


print2log ""
print2log "===== Security Scan Orchestrator Started ====="
print2log "Total scripts to process: $TOTAL_COUNT"
print2log ""

# ... (The rest of the script remains the same) ...
for i in "${!SCRIPTS_TO_RUN[@]}"; do
    script_path="${SCRIPTS_TO_RUN[$i]}"
    script_name=$(basename "$script_path")
    count=$((i + 1))

    print2log "[$count/$TOTAL_COUNT] ===== Executing $script_name ====="
    
    if [ -x "$script_path" ]; then
        print2log "Launching $script_name..."
        "$script_path"
        exit_code=$?

        if [ $exit_code -eq 0 ]; then
            print2log "SUCCESS: $script_name completed successfully."
            ((SUCCESS_COUNT++))
        else
            print2log "ERROR: $script_name failed with exit code $exit_code."
            ((FAILURE_COUNT++))
        fi
    else
        print2log "ERROR: $script_name not found or not executable at $script_path"
        ((FAILURE_COUNT++))
    fi
    
    print2log "[$count/$TOTAL_COUNT] ===== $script_name execution completed ====="
    print2log ""
done

# --- Trigger Email Notification ---
if [ "$SUCCESS_COUNT" -eq "$TOTAL_COUNT" ]; then
    print2log "All scans successful. Triggering email notification script..."
    /app/email.sh
else
    print2log "One or more scans failed. Skipping email notification."
fi
print2log ""

# --- Final Summary ---
print2log "===== All Scans Finished ====="
print2log "Total scripts processed: $TOTAL_COUNT"
print2log "Successful scripts: $SUCCESS_COUNT"
print2log "Failed scripts: $FAILURE_COUNT"
print2log "=============================="

if [ "$FAILURE_COUNT" -gt 0 ]; then
    exit 1
fi

exit 0