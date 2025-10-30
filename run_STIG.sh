#!/bin/bash
set -eo pipefail

# --- Configuration ---
HOST_ROOT="/host"
# The single directory for installation and results
SCC_DIR="${HOST_ROOT}/opt/scc"
SCANNER_CONTENT_DIR="/scanner_files/scc-5.10_rhel8_x86_64"
RESULTS_DIR="${SCC_DIR}/Resources/Results"

# Define the log file location inside the main SCC directory
LOG_FILE="${SCC_DIR}/stig_scan.log"

# --- Logging Function ---
print2log() {
  local message="$1"
  local timestamp=$(date +"%Y-%m-%d %H:%M:%S.%6N")
  mkdir -p "$(dirname "$LOG_FILE")"
  echo "[$timestamp] $message" | tee -a "$LOG_FILE"
}

# --- Main Logic ---

print2log "STIG scan process started from container."

# 1. Prepare SCC installation directory
# This command will now create /opt/scc on the host via the /host mount if podman hasn't already
print2log "Preparing SCC directory at ${SCC_DIR}..."
mkdir -p "${SCC_DIR}"

# 2. Extract and install the scanner
if [ -f "${SCC_DIR}/cscc" ]; then
    print2log "Scanner already installed at ${SCC_DIR}, skipping extraction..."
else
    print2log "Extracting scanner from ${SCANNER_CONTENT_DIR}..."
    cd "${SCANNER_CONTENT_DIR}"
    tar -xzf scc-5.10_rhel8_x86_64.tar.gz
    print2log "Copying scanner files to ${SCC_DIR}..."
    cp -rT scc_5.10/ "${SCC_DIR}/"
fi

# Copy benchmark if not already present
if [ ! -f "${SCC_DIR}/U_RHEL_8_V2R1_STIG_SCAP_1-3_Benchmark.zip" ]; then
    print2log "Copying STIG benchmark..."
    cp /scanner_files/U_RHEL_8_V2R1_STIG_SCAP_1-3_Benchmark.zip "${SCC_DIR}/"
else
    print2log "STIG benchmark already present, skipping copy..."
fi

# 3. Install the STIG benchmark profile
print2log "Installing STIG benchmark profile..."
chroot "${HOST_ROOT}" /opt/scc/cscc -is /opt/scc/U_RHEL_8_V2R1_STIG_SCAP_1-3_Benchmark.zip
if [ $? -ne 0 ]; then
    print2log "ERROR: Failed to install STIG benchmark profile."
    exit 1
fi

# 4. Run the scan
print2log "Starting STIG scan on host. This may take a while..."
mkdir -p "${SCC_DIR}/Resources/Results"

# Redirect stdout/stderr to a log file in the main SCC directory
chroot "${HOST_ROOT}" /opt/scc/cscc -u /opt/scc/Resources/Results/ > "${SCC_DIR}/output.txt" 2>&1
SCAN_EXIT_CODE=$?

if [ $SCAN_EXIT_CODE -ne 0 ]; then
    print2log "ERROR: STIG scan command failed with exit code $SCAN_EXIT_CODE. Check output.txt for details."
    exit 1
fi
print2log "STIG scan command completed."

print2log "Operation completed successfully."
print2log "Raw results and logs are located in /opt/scc on the host."
exit 0