#!/bin/bash
set -eo pipefail

# --- Configuration ---
HOST_ROOT="/host"
HOST_SCAN_DIR="${HOST_ROOT}/opt/scc"
LOG_FILE="${HOST_SCAN_DIR}/mail.log"

# --- SMTP Server (as requested) ---
SMTP_SERVER="smtp://smtp.gmail.com:587"

# --- Email Content (will be dynamically generated) ---
EMAIL_SUBJECT="Security Scan Results for $(cat /host/etc/hostname)"

print2log() {
    local message="$1"
    local timestamp
    timestamp=$(date +"%Y-%m-%d %H:%M:%S.%6N")
    # Ensure the log file's parent directory exists
    mkdir -p "$(dirname "$LOG_FILE")"
    echo "[$timestamp] $message" | tee -a "$LOG_FILE"
}

# --- Main Logic ---
print2log "--- Email notification script started ---"

# --- 1. Get Credentials ---
export RECIPIENT_EMAIL="${RECIPIENT_EMAIL:?Error: RECIPIENT_EMAIL not set}"
export SENDER_EMAIL="${SENDER_EMAIL:?Error: SENDER_EMAIL not set}"
export SMTP_USER="${SMTP_USER:?Error: SMTP_USER not set}"
export SMTP_PASS="${SMTP_PASS:?Error: SMTP_PASS not set}"

print2log "INFO: Credentials and configuration loaded."

# --- 2. Find Specific Reports for Scraping ---
print2log "INFO: Locating specific reports for data scraping..."
SESSIONS_DIR="${HOST_SCAN_DIR}/Resources/Results/Sessions"
OPENSCAP_DIR="${HOST_SCAN_DIR}/openscap_results"

LATEST_STIG_SESSION_DIR=$(find "$SESSIONS_DIR" -mindepth 1 -maxdepth 1 -type d 2>/dev/null | sort -r | head -n 1)
STIG_REPORT_FILE=$(find "${LATEST_STIG_SESSION_DIR}/Results/SCAP" -name "*All-Settings_RHEL_8_STIG*.html" 2>/dev/null | head -n 1)
PATCHED_REPORT_FILE=$(find "$OPENSCAP_DIR" -maxdepth 1 -name "*_patched_vulnerabilities.html" 2>/dev/null | sort -r | head -n 1)
UNPATCHED_REPORT_FILE=$(find "$OPENSCAP_DIR" -maxdepth 1 -name "*_unpatched_vulnerabilities.html" 2>/dev/null | sort -r | head -n 1)

# --- 3. Scrape Data from Reports ---
print2log "INFO: Scraping summary data from reports..."

# STIG Summary
if [ -f "$STIG_REPORT_FILE" ]; then
    print2log "INFO: Scraping STIG data from $(basename "$STIG_REPORT_FILE")"
    STIG_SCORE=$(grep 'Adjusted Score:' "$STIG_REPORT_FILE" | sed -n 's/.*<td class="label">Adjusted Score:<\/td><td class="value">\([^<]*\)<\/td>.*/\1/p')
    STIG_STATUS=$(grep 'Compliance Status:' "$STIG_REPORT_FILE" | sed -n 's/.*<td class="labelBold">Compliance Status:<\/td><td class="valueBold">\([^<]*\)<\/td>.*/\1/p')
    PASS_LINE=$(grep 'Pass:' "$STIG_REPORT_FILE" | grep '<td class="label">Pass:</td>')
    STIG_PASS=$(echo "$PASS_LINE" | sed -n 's/.*<td class="label">Pass:<\/td><td class="value">\([^<]*\)<\/td>.*/\1/p')
    STIG_NOT_APPLICABLE=$(echo "$PASS_LINE" | sed -n 's/.*<td class="label">Not Applicable:<\/td><td class="value">\([^<]*\)<\/td>.*/\1/p')
    FAIL_LINE=$(grep 'Fail:' "$STIG_REPORT_FILE" | grep '<td class="label">Fail:</td>')
    STIG_FAIL=$(echo "$FAIL_LINE" | sed -n 's/.*<td class="label">Fail:<\/td><td class="value">\([^<]*\)<\/td>.*/\1/p')
    STIG_NOT_CHECKED=$(echo "$FAIL_LINE" | sed -n 's/.*<td class="label">Not Checked:<\/td><td class="value">\([^<]*\)<\/td>.*/\1/p')
    TOTAL_LINE=$(grep 'Total:' "$STIG_REPORT_FILE" | grep '<td class="label">Total:</td>')
    STIG_TOTAL=$(echo "$TOTAL_LINE" | sed -n 's/.*<td class="label">Total:<\/td><td class="value">\([^<]*\)<\/td>.*/\1/p')
    
    export STIG_SCORE=$(echo "$STIG_SCORE" | xargs)
    export STIG_STATUS=$(echo "$STIG_STATUS" | xargs)
    export STIG_PASS=$(echo "$STIG_PASS" | xargs)
    export STIG_FAIL=$(echo "$STIG_FAIL" | xargs)
    export STIG_TOTAL=$(echo "$STIG_TOTAL" | xargs)
    export STIG_NOT_APPLICABLE=$(echo "$STIG_NOT_APPLICABLE" | xargs)
    export STIG_NOT_CHECKED=$(echo "$STIG_NOT_CHECKED" | xargs)
    print2log "INFO: STIG Data - Score: $STIG_SCORE, Status: $STIG_STATUS, Pass: $STIG_PASS, Fail: $STIG_FAIL, Total: $STIG_TOTAL, N/A: $STIG_NOT_APPLICABLE, Not Checked: $STIG_NOT_CHECKED"
else
    print2log "WARNING: STIG 'All-Settings' report not found. Summary will show N/A."
    export STIG_SCORE="N/A" STIG_STATUS="N/A" STIG_PASS="N/A" STIG_FAIL="N/A" STIG_TOTAL="N/A" STIG_NOT_APPLICABLE="N/A" STIG_NOT_CHECKED="N/A"
fi

# Patched Scan Summary
if [ -f "$PATCHED_REPORT_FILE" ]; then
    print2log "INFO: Scraping Patched OpenSCAP data from $(basename "$PATCHED_REPORT_FILE")"
    export PATCHED_FAIL=$(grep 'resultbadB' "$PATCHED_REPORT_FILE" | awk -F'[<>]' '{printf "%s", $3}')
    export PATCHED_PASS=$(grep 'resultgoodB' "$PATCHED_REPORT_FILE" | awk -F'[<>]' '{printf "%s", $3}')
    # Scrape Total using the provided HTML snippet pattern
    export PATCHED_TOTAL=$(sed -n 's/.*<td class="SmallText Center">\([0-9]\{1,\}\) Total.*/\1/p' "$PATCHED_REPORT_FILE" | head -n 1)
else
    print2log "WARNING: Patched OpenSCAP report not found. Summary will show N/A."
    export PATCHED_FAIL="N/A" PATCHED_PASS="N/A" PATCHED_TOTAL="N/A"
fi

# Unpatched Scan Summary
if [ -f "$UNPATCHED_REPORT_FILE" ]; then
    print2log "INFO: Scraping Unpatched OpenSCAP data from $(basename "$UNPATCHED_REPORT_FILE")"
    export UNPATCHED_FAIL=$(grep 'resultbadB' "$UNPATCHED_REPORT_FILE" | awk -F'[<>]' '{printf "%s", $3}')
    export UNPATCHED_PASS=$(grep 'resultgoodB' "$UNPATCHED_REPORT_FILE" | awk -F'[<>]' '{printf "%s", $3}')
    # Scrape Total using the provided HTML snippet pattern
    export UNPATCHED_TOTAL=$(sed -n 's/.*<td class="SmallText Center">\([0-9]\{1,\}\) Total.*/\1/p' "$UNPATCHED_REPORT_FILE" | head -n 1)
else
    print2log "WARNING: Unpatched OpenSCAP report not found. Summary will show N/A."
    export UNPATCHED_FAIL="N/A" UNPATCHED_PASS="N/A" UNPATCHED_TOTAL="N/A"
fi

# --- 4. Prepare Variables for HTML Email Body ---
print2log "INFO: Preparing variables for HTML email body..."
export HOSTNAME=$(cat /host/etc/hostname)
export SCAN_DATE=$(date +"%Y-%m-%d %H:%M:%S")
export EMAIL_SUBJECT="Security Scan Results for $HOSTNAME" # Re-set subject with hostname

# Determine status color
case "$STIG_STATUS" in
    *"GREEN"*|*"green"*) STATUS_COLOR="#28a745";;
    *"BLUE"*|*"blue"*) STATUS_COLOR="#007bff";;
    *"YELLOW"*|*"yellow"*) STATUS_COLOR="#ffc107";;
    *"RED"*|*"red"*) STATUS_COLOR="#dc3545";;
    *) STATUS_COLOR="#6c757d";;
esac
export STATUS_COLOR

# --- 5. Find All Reports for Attachment ---
declare -a attachments=()
print2log "INFO: Searching for all report files to attach..."

# OpenSCAP Reports
if [ -d "$OPENSCAP_DIR" ] && [ -n "$(ls -A "$OPENSCAP_DIR")" ]; then
    while IFS= read -r file; do
        if [ -f "$file" ]; then
            attachments+=("$file")
            print2log "INFO: Attaching OpenSCAP report: $(basename "$file")"
        fi
    done < <(find "$OPENSCAP_DIR" -maxdepth 1 -name "*.html")
fi

# STIG Reports
if [ -d "$SESSIONS_DIR" ] && [ -n "$(ls -A "$SESSIONS_DIR")" ]; then
    LATEST_STIG_DIR="${SESSIONS_DIR}/$(ls -1t "$SESSIONS_DIR" | head -n 1)/Results/SCAP"
    if [ -d "$LATEST_STIG_DIR" ]; then
        while IFS= read -r file; do
            if [ -f "$file" ]; then
                attachments+=("$file")
                print2log "INFO: Attaching STIG report: $(basename "$file")"
            fi
        done < <(find "$LATEST_STIG_DIR" -name "*.html")
    fi
fi

# --- 6. Send Email using Python ---
if [ "${#attachments[@]}" -eq 0 ]; then
    print2log "WARNING: No HTML reports found to attach. Nothing to send."
    exit 0
fi

# Pass attachments array as a space-separated string
export ATTACHMENT_FILES="${attachments[*]}"

# Parse SMTP host and port for Python
export SMTP_HOST=$(echo "$SMTP_SERVER" | sed -e 's,smtp://,,g' -e 's,:.*,,g')
export SMTP_PORT=$(echo "$SMTP_SERVER" | sed -e 's,.*:,,g')
if [ -z "$SMTP_PORT" ]; then
    export SMTP_PORT=587 # Default to 587 if not specified
fi

print2log "INFO: Connecting to $SMTP_HOST:$SMTP_PORT..."
print2log "INFO: Sending email with HTML body and ${#attachments[@]} attachments via Python..."

# Use python3 to send a MIME-compliant email
# We pass all data via environment variables
python3 -c '
import os
import smtplib
import mimetypes
from email.message import EmailMessage
from email.utils import formatdate

# --- Get data from Environment Variables ---
sender = os.environ.get("SENDER_EMAIL")
recipient = os.environ.get("RECIPIENT_EMAIL")
subject = os.environ.get("EMAIL_SUBJECT")
smtp_host = os.environ.get("SMTP_HOST")
smtp_port = int(os.environ.get("SMTP_PORT", 587))
smtp_user = os.environ.get("SMTP_USER")
smtp_pass = os.environ.get("SMTP_PASS")

# --- Get scraped data for HTML body ---
hostname = os.environ.get("HOSTNAME")
scan_date = os.environ.get("SCAN_DATE")
status_color = os.environ.get("STATUS_COLOR")
stig_score = os.environ.get("STIG_SCORE")
stig_status = os.environ.get("STIG_STATUS")
stig_total = os.environ.get("STIG_TOTAL")
stig_pass = os.environ.get("STIG_PASS")
stig_fail = os.environ.get("STIG_FAIL")
stig_na = os.environ.get("STIG_NOT_APPLICABLE")
stig_nc = os.environ.get("STIG_NOT_CHECKED")
patched_pass = os.environ.get("PATCHED_PASS")
patched_fail = os.environ.get("PATCHED_FAIL")
patched_total = os.environ.get("PATCHED_TOTAL")
unpatched_pass = os.environ.get("UNPATCHED_PASS")
unpatched_fail = os.environ.get("UNPATCHED_FAIL")
unpatched_total = os.environ.get("UNPATCHED_TOTAL")

# --- Build the HTML Body ---
html_body = f"""
<html>
<body style="font-family: Arial, sans-serif; margin: 20px;">
<h2>System Security Scan Summary</h2>
<p style="font-size: 14px; color: #333;">Here is a high-level summary of the latest security scans for <b>{hostname}</b>.</p>
<p><b>Hostname:</b> {hostname}<br>
<b>Date:</b> {scan_date}</p>

<!-- 1. Vulnerabilities Scan Report -->
<h3 style="margin-top: 25px;">Vulnerabilities Scan Report</h3>
<table style="width: 600px; border-collapse: collapse; border: 2px solid #333; margin-top: 15px;">
<tr style="background-color: #f2f2f2;">
<td style="width: 200px; border: 1px solid #999; padding: 8px; background-color: #f2f2f2;">Total</td>
<td style="border: 1px solid #999; padding: 8px; background-color: #f2f2f2;">{patched_total}</td>
</tr>
<tr>
<td style="width: 200px; border: 1px solid #999; padding: 8px;">Patched</td>
<td style="border: 1px solid #999; padding: 8px; color: green;">{patched_pass}</td>
</tr>
<tr style="background-color: #f2f2f2;">
<td style="width: 200px; border: 1px solid #999; padding: 8px; background-color: #f2f2f2;">Vulnerable</td>
<td style="border: 1px solid #999; padding: 8px; color: red;">{patched_fail}</td>
</tr>
</table>

<!-- 2. STIG Compliance Summary -->
<h3 style="margin-top: 25px;">STIG Compliance Summary</h3>
<table style="width: 600px; border-collapse: collapse; border: 2px solid #333; margin-top: 15px;">
<tr style="background-color: #f2f2f2;">
<td style="width: 200px; border: 1px solid #999; padding: 8px; background-color: #f2f2f2;">Adjusted Score</td>
<td style="border: 1px solid #999; padding: 8px; background-color: #f2f2f2;">{stig_score}</td>
</tr>
<tr>
<td style="width: 200px; border: 1px solid #999; padding: 8px;">Compliance Status</td>
<td style="border: 1px solid #999; padding: 8px; background-color: {status_color}; color: white;">{stig_status}</td>
</tr>
<tr style="background-color: #f2f2f2;">
<td style="width: 200px; border: 1px solid #999; padding: 8px; background-color: #f2f2f2;">Total Checks</td>
<td style="border: 1px solid #999; padding: 8px; background-color: #f2f2f2;">{stig_total}</td>
</tr>
<tr>
<td style="width: 200px; border: 1px solid #999; padding: 8px;">Passed</td>
<td style="border: 1px solid #999; padding: 8px; color: green;">{stig_pass}</td>
</tr>
<tr style="background-color: #f2f2f2;">
<td style="width: 200px; border: 1px solid #999; padding: 8px; background-color: #f2f2f2;">Failed</td>
<td style="border: 1px solid #999; padding: 8px; color: red;">{stig_fail}</td>
</tr>
<tr>
<td style="width: 200px; border: 1px solid #999; padding: 8px;">Not Applicable</td>
<td style="border: 1px solid #999; padding: 8px;">{stig_na}</td>
</tr>
<tr style="background-color: #f2f2f2;">
<td style="width: 200px; border: 1px solid #999; padding: 8px; background-color: #f2f2f2;">Not Checked</td>
<td style="border: 1px solid #999; padding: 8px; background-color: #f2f2f2;">{stig_nc}</td>
</tr>
<tr>
<td colspan="2" style="border: 1px solid #999; padding: 10px; font-size: 12px; line-height: 1.4; background-color: #fafafa;">
    <b>Color Key:</b><br>
    <span style="color: #007bff;">&#9632;</span> <b>BLUE:</b> Score equals 100<br>
    <span style="color: #28a745;">&#9632;</span> <b>GREEN:</b> Score is greater than or equal to 90<br>
    <span style="color: #ffc107;">&#9632;</span> <b>YELLOW:</b> Score is greater than or equal to 80<br>
    <span style="color: #dc3545;">&#9632;</span> <b>RED:</b> Score is greater than or equal to 0
</td>
</tr>
</table>

<!-- 3. Unpatched Vulnerabilities Report -->
<h3 style="margin-top: 25px;">Unpatched Vulnerabilities Report</h3>
<table style="width: 600px; border-collapse: collapse; border: 2px solid #333; margin-top: 15px;">
<tr style="background-color: #f2f2f2;">
<td style="width: 200px; border: 1px solid #999; padding: 8px; background-color: #f2f2f2;">Total</td>
<td style="border: 1px solid #999; padding: 8px; background-color: #f2f2f2;">{unpatched_total}</td>
</tr>
<tr>
<td style="width: 200px; border: 1px solid #999; padding: 8px;">Patched</td>
<td style="border: 1px solid #999; padding: 8px; color: green;">{unpatched_pass}</td>
</tr>
<tr style="background-color: #f2f2f2;">
<td style="width: 200px; border: 1px solid #999; padding: 8px; background-color: #f2f2f2;">Vulnerable</td>
<td style="border: 1px solid #999; padding: 8px; color: red;">{unpatched_fail}</td>
</tr>
</table>

<p style="margin-top: 25px; font-size: 12px; color: #888;">This is an automated message. Full, detailed HTML reports are attached to this email.</p>
</body>
</html>
"""

# --- Create the Email Message ---
msg = EmailMessage()
msg["Subject"] = subject
msg["From"] = sender
msg["To"] = recipient
msg["Date"] = formatdate(localtime=True)
msg.set_content("Please enable HTML to view this report.") # Fallback for non-HTML clients

# Add the HTML body
msg.add_alternative(html_body, subtype="html")

# --- Add Attachments ---
attachment_paths = os.environ.get("ATTACHMENT_FILES", "").split()
for path in attachment_paths:
    if not os.path.isfile(path):
        print(f"Attachment not found: {path}")
        continue
    
    ctype, encoding = mimetypes.guess_type(path)
    if ctype is None or encoding is not None:
        ctype = "application/octet-stream" # Default
    
    maintype, subtype = ctype.split("/", 1)
    
    with open(path, "rb") as fp:
        msg.add_attachment(
            fp.read(),
            maintype=maintype,
            subtype=subtype,
            filename=os.path.basename(path)
        )

# --- Send the Email ---
try:
    with smtplib.SMTP(smtp_host, smtp_port) as s:
        s.ehlo()
        s.starttls()
        s.ehlo()
        s.login(smtp_user, smtp_pass)
        s.send_message(msg)
    print("Python: Email sent successfully.")
except Exception as e:
    print(f"Python: Error sending email: {e}")
    exit(1)
'

MAIL_EXIT_CODE=$?

if [ $MAIL_EXIT_CODE -eq 0 ]; then
    print2log "SUCCESS: Email sent successfully."
else
    print2log "FAILURE: Python email script failed. Check logs."
    exit 1
fi

print2log "--- Email notification script finished ---"
exit 0