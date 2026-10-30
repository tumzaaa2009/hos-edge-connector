#!/usr/bin/env bash
# ==============================================================================
# SOC & Wazuh Active Response: quarantine.sh (Linux)
# Quarantines suspicious files to /var/ossec/quarantine/ with 0000 permissions
# ==============================================================================

LOG_FILE="/var/ossec/logs/active-responses.log"
QUARANTINE_DIR="/var/ossec/quarantine"

mkdir -p "$QUARANTINE_DIR" 2>/dev/null
chmod 700 "$QUARANTINE_DIR" 2>/dev/null

INPUT_JSON=$(cat)

# Safeguard: Do not quarantine on Manager if alert originated from a remote agent
ALERT_AGENT_ID=$(echo "$INPUT_JSON" | jq -r '.parameters.alert.agent.id // "000"' 2>/dev/null || echo "000")
if [ "$ALERT_AGENT_ID" != "000" ] && [ -f /var/ossec/bin/wazuh-analysisd ]; then
    echo "$(date '+%Y/%m/%d %H:%M:%S') quarantine.sh: [INFO] Skipping quarantine on Manager for remote agent.id=$ALERT_AGENT_ID" >> "$LOG_FILE" 2>/dev/null || true
    exit 0
fi

FILEPATH=$(echo "$INPUT_JSON" | jq -r '.parameters.alert.syscheck.path // .parameters.alert.data.file // .parameters.alert.data.audit.file.name // .parameters.alert.data.audit.exe // .parameters.extra_args[0] // empty' 2>/dev/null)

if [ -z "$FILEPATH" ] || [ "$FILEPATH" == "null" ]; then
    echo "$(date '+%Y/%m/%d %H:%M:%S') quarantine.sh: [ERROR] No valid file path provided" >> "$LOG_FILE" 2>/dev/null || true
    exit 0
fi

if [ ! -f "$FILEPATH" ]; then
    echo "$(date '+%Y/%m/%d %H:%M:%S') quarantine.sh: [WARN] File not found: $FILEPATH" >> "$LOG_FILE" 2>/dev/null || true
    exit 0
fi

# Critical OS / HIS Protection: Refuse to quarantine system binaries or config
if [[ "$FILEPATH" =~ ^/(bin|sbin|lib|lib64|usr/bin|usr/sbin|etc/passwd|etc/shadow|etc/sudoers|var/ossec/bin) ]]; then
    echo "$(date '+%Y/%m/%d %H:%M:%S') quarantine.sh: [WARN] Refusing to quarantine core system path: $FILEPATH" >> "$LOG_FILE" 2>/dev/null || true
    exit 0
fi

FILENAME=$(basename "$FILEPATH")
TIMESTAMP=$(date '+%Y%m%d_%H%M%S')
DEST="$QUARANTINE_DIR/${TIMESTAMP}_${FILENAME}"

SHA256=$(sha256sum "$FILEPATH" 2>/dev/null | awk '{print $1}')
mv -f "$FILEPATH" "$DEST" 2>/dev/null
chmod 0000 "$DEST" 2>/dev/null

echo "$(date '+%Y/%m/%d %H:%M:%S') quarantine.sh: [QUARANTINED] file=$FILEPATH dest=$DEST sha256=$SHA256" >> "$LOG_FILE" 2>/dev/null || true
exit 0
