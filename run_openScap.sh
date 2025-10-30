#!/bin/bash
set -eo pipefail

HOST_ROOT="/host"
SCC_DIR="${HOST_ROOT}/opt/scc"
OUTPUT_DIR="${SCC_DIR}/openscap_results"
TIMESTAMP=$(date +"%Y-%m-%d_%H%M%S")
LOG_FILE="${OUTPUT_DIR}/${TIMESTAMP}_scan.log"

print2log() {
  local message="$1"
  local timestamp
  timestamp=$(date +"%Y-%m-%d %H:%M:%S.%6N")
  mkdir -p "$(dirname "$LOG_FILE")"
  echo "[$timestamp] $message" | tee -a "$LOG_FILE"
}

mkdir -p "${OUTPUT_DIR}"
print2log "--- OpenSCAP Scan Started: $(date) ---"

print2log "INFO: Downloading OVAL file for patched vulnerabilities..."
wget -q -O - https://security.access.redhat.com/data/oval/v2/RHEL8/rhel-8.oval.xml.bz2   | bzip2 --decompress > rhel-8.oval.xml
if [ $? -eq 0 ]; then
  print2log "SUCCESS: OVAL file for patched scan downloaded."
else
  print2log "FAILURE: Failed to download OVAL file for patched scan. Exiting."
  exit 1
fi

print2log "INFO: Running OpenSCAP evaluation on the host VM for patched scan..."
oscap oval eval --report "${OUTPUT_DIR}/${TIMESTAMP}_patched_vulnerabilities.html" rhel-8.oval.xml &> /dev/null
if [ $? -eq 0 ]; then
  print2log "SUCCESS: Patched vulnerability scan complete."
else
  print2log "FAILURE: 'oscap' command failed for the patched scan. Exiting."
  exit 1
fi

print2log "INFO: Downloading OVAL file for UNPATCHED vulnerabilities..."
wget -q -O - https://security.access.redhat.com/data/oval/v2/RHEL8/rhel-8-including-unpatched.oval.xml.bz2 | bzip2 --decompress > rhel-8-including-unpatched.xml
if [ $? -eq 0 ]; then
  print2log "SUCCESS: OVAL file for unpatched scan downloaded."
else
  print2log "FAILURE: Failed to download OVAL file for unpatched scan. Exiting."
  exit 1
fi

print2log "INFO: Running OpenSCAP evaluation on the host VM for unpatched scan..."
oscap oval eval --report "${OUTPUT_DIR}/${TIMESTAMP}_unpatched_vulnerabilities.html" rhel-8-including-unpatched.xml &> /dev/null
if [ $? -eq 0 ]; then
  print2log "SUCCESS: Unpatched vulnerability scan complete."
else
  print2log "FAILURE: 'oscap' command failed for the unpatched scan. Exiting."
  exit 1
fi

print2log "INFO: Cleaning up temporary OVAL file..."
rm rhel-8.oval.xml rhel-8-including-unpatched.xml
if [ $? -eq 0 ]; then
  print2log "SUCCESS: Cleanup complete."
else
  print2log "FAILURE: Failed to clean up temporary file. Exiting."
  exit 1
fi

print2log "All scans finished successfully."
print2log "Results are located in /opt/scc/openscap_results on the host."
print2log "--- OpenSCAP Scan Finished: $(date) ---"
exit 0