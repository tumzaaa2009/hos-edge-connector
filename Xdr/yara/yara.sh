#!/bin/bash
# =============================================================
# YARA Active Response สำหรับ Linux Agent (Native, I/O-optimized)
# ติดตั้งที่: /var/ossec/active-response/bin/yara.sh
# =============================================================

export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:$PATH"

LOGFILE="/var/ossec/logs/active-responses.log"
MAX_SCAN_SIZE_MB="${YARA_MAX_SCAN_SIZE_MB:-100}"

echo "$(date '+%Y/%m/%d %H:%M:%S') /var/ossec/active-response/bin/yara.sh: Starting" >> "$LOGFILE"

read INPUT_JSON

json_extract() {
    local filter="$1"
    if command -v jq >/dev/null 2>&1; then
        echo "$INPUT_JSON" | jq -r "$filter" 2>/dev/null
    elif command -v python3 >/dev/null 2>&1; then
        echo "$INPUT_JSON" | python3 -c "
import sys, json
try:
    d = json.loads(sys.stdin.read())
    for f in '$filter'.split('//'):
        f = f.strip().split()
        val = d
        for k in f[0].strip('.').split('.'):
            if isinstance(val, dict):
                val = val.get(k)
            elif isinstance(val, list) and k.isdigit():
                val = val[int(k)] if int(k) < len(val) else None
            else:
                val = None
        if val is not None and val != 'null':
            print(val)
            sys.exit(0)
except Exception:
    pass
" 2>/dev/null
    else
        echo "$INPUT_JSON" | grep -o -E '"'"$(echo "$filter" | awk -F'.' '{print $NF}')"'":[0-9.a-zA-Z_-]+' | cut -d: -f2 | tr -d '"' | head -n 1
    fi
}

FILEPATH=$(json_extract '.parameters.alert.syscheck.path')
if [ "$FILEPATH" == "null" ] || [ -z "$FILEPATH" ]; then
    echo "$(date -Is) yara.sh: [DEBUG] No path in syscheck, checking extra_args." >> "$LOGFILE"
    FILEPATH=$(json_extract '.parameters.extra_args[0]')
fi

if [ -z "$FILEPATH" ] || [ "$FILEPATH" == "null" ]; then
    echo "$(date -Is) yara.sh: [ERROR] No valid file path parsed from input." >> "$LOGFILE"
    logger -p local6.err -t wazuh_yara -- \
    "{\"event\":\"yara\",\"action\":\"error\",\"level\":\"ERROR\",\"reason\":\"no_file_path\"}"
    exit 0
fi

ALERT_AGENT_ID=$(json_extract '.parameters.alert.agent.id // empty')
if [ -n "$ALERT_AGENT_ID" ] && [ "$ALERT_AGENT_ID" != "000" ] && [ -f "/var/ossec/bin/wazuh-analysisd" ]; then
    echo "$(date -Is) yara.sh: [INFO] SKIP_REMOTE_AGENT: File path belongs to agent $ALERT_AGENT_ID, skipping local manager scan." >> "$LOGFILE"
    exit 0
fi

if [ ! -f "$FILEPATH" ]; then
    echo "$(date -Is) yara.sh: [ERROR] File not found on disk path=$FILEPATH" >> "$LOGFILE"
    logger -p local6.err -t wazuh_yara -- \
    "{\"event\":\"yara\",\"action\":\"error\",\"level\":\"ERROR\",\"reason\":\"file_not_found\",\"file\":\"$FILEPATH\"}"
    exit 0
fi

FILENAME=$(basename "$FILEPATH")
ABS_FILE=$(realpath "$FILEPATH")

AUDIT_PID=$(json_extract '.parameters.alert.syscheck.audit.process.id // empty')
AUDIT_PPID=$(json_extract '.parameters.alert.syscheck.audit.process.ppid // empty')
AUDIT_USER=$(json_extract '.parameters.alert.syscheck.audit.user.name // .parameters.alert.syscheck.audit.login_user.name // empty')
SRC_IP=$(json_extract '.parameters.alert.data.srcip // .parameters.alert.srcip // .parameters.alert.data.src_ip // .parameters.alert.syscheck.audit.srcip // empty')
[ "$SRC_IP" == "null" ] && SRC_IP=""
[ "$AUDIT_USER" == "null" ] && AUDIT_USER=""

FILE_SIZE_BYTES=$(stat -c '%s' "$ABS_FILE" 2>/dev/null || echo 0)
MAX_SCAN_SIZE_BYTES=$((MAX_SCAN_SIZE_MB * 1024 * 1024))
if [ "$FILE_SIZE_BYTES" -gt "$MAX_SCAN_SIZE_BYTES" ]; then
    echo "$(date -Is) yara.sh: [INFO] SKIP_LARGE_FILE file=$ABS_FILE size=${FILE_SIZE_BYTES}B (limit=${MAX_SCAN_SIZE_MB}MB)" >> "$LOGFILE"
    logger -p local6.info -t wazuh_yara -- \
    "{\"event\":\"yara\",\"action\":\"skip_large_file\",\"level\":\"INFO\",\"file\":\"$ABS_FILE\",\"size_bytes\":\"$FILE_SIZE_BYTES\"}"
    echo "$(date '+%Y/%m/%d %H:%M:%S') /var/ossec/active-response/bin/yara.sh: Ended" >> "$LOGFILE"
    exit 0
fi

echo "$(date -Is) yara.sh: [INFO] SCAN_START file=$ABS_FILE size=${FILE_SIZE_BYTES}B" >> "$LOGFILE"

YARA_RULES_COMPILED=""
for cand in "/var/ossec/etc/shared/yara_rules.yc" "/var/ossec/etc/shared/default/yara_rules.yc"; do
    if [ -f "$cand" ]; then
        YARA_RULES_COMPILED="$cand"
        break
    fi
done

YARA_RULES=""
for cand in "/var/ossec/etc/shared/yara_rules.yar" "/var/ossec/etc/shared/default/yara_rules.yar"; do
    if [ -f "$cand" ]; then
        YARA_RULES="$cand"
        break
    fi
done

YARA_BIN=$(command -v yara 2>/dev/null || echo "/usr/bin/yara")
[ ! -x "$YARA_BIN" ] && [ -x "/usr/bin/yara" ] && YARA_BIN="/usr/bin/yara"

if [ -n "$YARA_RULES_COMPILED" ]; then
    YARA_CMD="$YARA_BIN -C $YARA_RULES_COMPILED"
elif [ -n "$YARA_RULES" ]; then
    YARA_CMD="$YARA_BIN -r $YARA_RULES"
else
    echo "$(date -Is) yara.sh: [ERROR] YARA rules not found." >> "$LOGFILE"
    logger -p local6.err -t wazuh_yara -- \
    "{\"event\":\"yara\",\"action\":\"error\",\"level\":\"ERROR\",\"reason\":\"rules_not_found\"}"
    exit 1
fi

echo "$(date -Is) yara.sh: [INFO] Waiting 1s for IO sync..." >> "$LOGFILE"
sleep 1

RUNNING_SCANS=$(pgrep -x "yara" 2>/dev/null | wc -l)
RUNNING_SCANS="${RUNNING_SCANS:-0}"
if [ "$RUNNING_SCANS" -ge 5 ]; then
    echo "$(date -Is) yara.sh: [INFO] SKIP: Max concurrent YARA scans ($RUNNING_SCANS) reached. Throttling to protect system performance." >> "$LOGFILE"
    exit 0
fi

echo "$(date -Is) yara.sh: [DEBUG] Executing YARA scan with lowest CPU/IO priority (nice/ionice)..." >> "$LOGFILE"

# Execute with lowest CPU priority (nice -n 19) and lowest disk I/O priority (ionice -c 3)
if command -v ionice >/dev/null 2>&1; then
    YARA_RESULT=$(nice -n 19 ionice -c 3 $YARA_CMD "$ABS_FILE" 2>&1)
else
    YARA_RESULT=$(nice -n 19 $YARA_CMD "$ABS_FILE" 2>&1)
fi
EXIT_CODE=$?

echo "$(date -Is) yara.sh: [DEBUG] YARA execution finished. Exit Code: $EXIT_CODE" >> "$LOGFILE"

CLEAN_YARA_RESULT=$(echo "$YARA_RESULT" | grep -vi warning)

if [ -n "$CLEAN_YARA_RESULT" ] && [ "$EXIT_CODE" -eq 0 ]; then

    FILE_OWNER=$(stat -c '%U' "$ABS_FILE" 2>/dev/null)
    DETECT_USER="${AUDIT_USER:-$FILE_OWNER}"
    [ -z "$DETECT_USER" ] && DETECT_USER="N/A"

    if [ -z "$SRC_IP" ] && [ -n "$AUDIT_PID" ] && [ "$AUDIT_PID" != "null" ]; then
        SRC_IP=$(ss -tnp 2>/dev/null | grep -E "pid=($AUDIT_PID|$AUDIT_PPID)," | awk '{print $5}' | cut -d: -f1 | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' | head -n 1)
        if [ -z "$SRC_IP" ] && [ -r "/proc/$AUDIT_PID/environ" ]; then
            SRC_IP=$(tr '\0' '\n' < "/proc/$AUDIT_PID/environ" 2>/dev/null | grep -E '^SSH_CLIENT=' | cut -d= -f2 | awk '{print $1}')
        fi
        if [ -z "$SRC_IP" ] && [ -n "$AUDIT_PPID" ] && [ -r "/proc/$AUDIT_PPID/environ" ]; then
            SRC_IP=$(tr '\0' '\n' < "/proc/$AUDIT_PPID/environ" 2>/dev/null | grep -E '^SSH_CLIENT=' | cut -d= -f2 | awk '{print $1}')
        fi
    fi
    if [ -z "$SRC_IP" ] && [ "$DETECT_USER" != "N/A" ]; then
        SRC_IP=$(who 2>/dev/null | grep "^$DETECT_USER" | awk '{print $5}' | tr -d '()' | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' | head -n 1)
        [ -z "$SRC_IP" ] && SRC_IP=$(last -n 10 "$DETECT_USER" 2>/dev/null | grep -o -E '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' | head -n 1)
    fi
    if [ -z "$SRC_IP" ] && [ -n "$SSH_CLIENT" ]; then
        SRC_IP=$(echo "$SSH_CLIENT" | awk '{print $1}')
    fi
    if [ -z "$SRC_IP" ]; then
        SRC_IP=$(ss -tn '( sport = :22 or sport = :80 or sport = :443 )' 2>/dev/null | awk 'NR>1 {print $5}' | cut -d: -f1 | grep -vE '^(127\.|::1|0\.0\.0\.0)' | head -n 1)
    fi
    [ -z "$SRC_IP" ] && SRC_IP="127.0.0.1"

    echo "$(date -Is) yara.sh: [WARN] MALWARE_DETECTED file=$FILENAME result=$CLEAN_YARA_RESULT src_ip=$SRC_IP user=$DETECT_USER" >> "$LOGFILE"

    SHA256=$(sha256sum "$ABS_FILE" | awk '{print $1}')
    MD5=$(md5sum "$ABS_FILE" | awk '{print $1}')

    echo "$(date -Is) yara.sh: [DEBUG] Hashes computed. SHA256=$SHA256" >> "$LOGFILE"

    YARA_CLEAN_FORMAT=$(echo "$CLEAN_YARA_RESULT" | awk '{print $1}' | tr '\n' ',' | sed 's/,$//')

    logger -p local6.notice -t wazuh_yara -- \
    "{\"event\":\"yara\",\"action\":\"detect\",\"level\":\"INFO\",\"rule\":\"$YARA_CLEAN_FORMAT\",\"file\":\"$ABS_FILE\",\"sha256\":\"$SHA256\",\"md5\":\"$MD5\",\"src_ip\":\"$SRC_IP\",\"user\":\"$DETECT_USER\"}"

    # Critical OS / Infrastructure Protection: Refuse to delete core system binaries
    if [[ "$ABS_FILE" =~ ^/(bin|sbin|lib|lib64|usr/bin|usr/sbin|etc/passwd|etc/shadow|etc/sudoers|var/ossec/bin) ]]; then
        echo "$(date -Is) yara.sh: [WARN] Refusing to quarantine core system path: $ABS_FILE" >> "$LOGFILE"
        logger -p local6.warn -t wazuh_yara -- \
        "{\"event\":\"yara\",\"action\":\"quarantine_skipped\",\"level\":\"WARN\",\"reason\":\"protected_system_path\",\"file\":\"$ABS_FILE\"}"
    else
        # Safe Quarantine: Move to /var/ossec/quarantine/ with 0000 permissions (Reversible, Forensic-ready)
        QUARANTINE_DIR="/var/ossec/quarantine"
        mkdir -p "$QUARANTINE_DIR" 2>/dev/null
        chmod 700 "$QUARANTINE_DIR" 2>/dev/null
        TIMESTAMP=$(date '+%Y%m%d_%H%M%S')
        DEST="$QUARANTINE_DIR/${TIMESTAMP}_${FILENAME}"

        mv -f "$ABS_FILE" "$DEST" 2>/dev/null
        chmod 0000 "$DEST" 2>/dev/null

        if [ -f "$DEST" ] && [ ! -f "$ABS_FILE" ]; then
            echo "$(date -Is) yara.sh: [DEBUG] File safely quarantined to $DEST" >> "$LOGFILE"
            echo "$(date -Is) wazuh-yara: src=$ABS_FILE dest=$DEST sha256=$SHA256 md5=$MD5 yara_match=$YARA_CLEAN_FORMAT src_ip=$SRC_IP user=$DETECT_USER cdb_format=$SHA256:$YARA_CLEAN_FORMAT" >> "$LOGFILE"
            logger -p local6.notice -t wazuh_yara -- \
            "{\"event\":\"yara\",\"action\":\"quarantined\",\"level\":\"INFO\",\"rule\":\"$YARA_CLEAN_FORMAT\",\"src\":\"$ABS_FILE\",\"dest\":\"$DEST\",\"sha256\":\"$SHA256\"}"
        else
            echo "$(date -Is) yara.sh: [ERROR] Failed to quarantine file." >> "$LOGFILE"
            logger -p local6.err -t wazuh_yara -- \
            "{\"event\":\"yara\",\"action\":\"quarantine_failed\",\"level\":\"ERROR\",\"rule\":\"$YARA_CLEAN_FORMAT\",\"file\":\"$ABS_FILE\",\"sha256\":\"$SHA256\",\"md5\":\"$MD5\",\"src_ip\":\"$SRC_IP\",\"user\":\"$DETECT_USER\"}"
        fi
    fi

else

    if [ "$EXIT_CODE" -ne 0 ]; then
        YARA_ERR_CLEAN=$(echo "$YARA_RESULT" | tr '\n' ' ' | sed 's/  */ /g')
        echo "$(date -Is) yara.sh: [ERROR] YARA scan failed. Result: $YARA_RESULT" >> "$LOGFILE"
        logger -p local6.err -t wazuh_yara -- \
        "{\"event\":\"yara\",\"action\":\"scan_error\",\"level\":\"ERROR\",\"reason\":\"$YARA_ERR_CLEAN\",\"file\":\"$ABS_FILE\"}"
    else
        echo "$(date -Is) yara.sh: [INFO] CLEAN file=$FILENAME" >> "$LOGFILE"
        logger -p local6.info -t wazuh_yara -- \
        "{\"event\":\"yara\",\"action\":\"clean\",\"level\":\"INFO\",\"file\":\"$ABS_FILE\"}"
    fi

fi

echo "$(date '+%Y/%m/%d %H:%M:%S') /var/ossec/active-response/bin/yara.sh: Ended" >> "$LOGFILE"
exit 0
