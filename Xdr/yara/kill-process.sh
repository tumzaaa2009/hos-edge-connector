#!/bin/bash
# active-response/bin/kill-process.sh
# Reads Wazuh AR JSON from stdin, kills the offending PID, logs result.

LOG_FILE="/var/ossec/logs/active-responses.log"

INPUT_JSON=$(cat)

# Safeguard: Do not kill process on Manager if alert originated from a remote agent
ALERT_AGENT_ID=$(echo "$INPUT_JSON" | jq -r '.parameters.alert.agent.id // "000"' 2>/dev/null || echo "000")
if [ "$ALERT_AGENT_ID" != "000" ] && [ -f /var/ossec/bin/wazuh-analysisd ]; then
    echo "$(date '+%Y-%m-%dT%H:%M:%S%z') kill-process.sh: Safeguard: Skipped killing process on Manager for remote agent.id=$ALERT_AGENT_ID." >> "$LOG_FILE" 2>/dev/null || true
    exit 0
fi

COMMAND=$(echo "$INPUT_JSON" | jq -r .command 2>/dev/null)
if [ "$COMMAND" = "add" ]; then
    PROCID=$(echo "$INPUT_JSON" | jq -r '.parameters.alert.data.audit.pid // .parameters.alert.data.audit.process.id // .parameters.alert.data.audit.process.pid // .parameters.alert.data.audit.execve.pid // .parameters.alert.data.process.id // .parameters.alert.data.process.pid // .parameters.alert.data.pid // .parameters.alert.data.win.eventdata.sourceProcessId // .parameters.alert.data.win.eventdata.processId // .parameters.extra_args[0] // empty' 2>/dev/null)
    IMAGE=$(echo "$INPUT_JSON" | jq -r '.parameters.alert.data.audit.exe // .parameters.alert.data.audit.command // .parameters.alert.data.win.eventdata.sourceImage // .parameters.alert.data.win.eventdata.image // empty' 2>/dev/null)
    
    if [ -z "$PROCID" ] || [ "$PROCID" == "null" ]; then
        echo "$(date '+%Y-%m-%dT%H:%M:%S%z') kill-process.sh: No processID present in alert data — aborting." >> "$LOG_FILE" 2>/dev/null || true
        exit 0
    fi

    # Regulator & Hospital HIS Safeguard: Never kill critical OS, DB, HIS, Web, or Wazuh services
    PCOMM=$(ps -p "$PROCID" -o comm= 2>/dev/null || true)
    PROTECTED_HIS_REGEX="^(systemd|init|sshd|wazuh-.*|ossec-.*|auditd|mysqld|mariadb|postgres|postmaster|oracle|java|node|nginx|apache2|httpd|php-fpm|php|docker|containerd|dockerd|redis-server|mongod|hisservice|his-.*)$"
    if [[ "$PCOMM" =~ $PROTECTED_HIS_REGEX ]] || [ "$PROCID" -le 300 ]; then
        echo "$(date '+%Y-%m-%dT%H:%M:%S%z') kill-process.sh: Safeguard: Skipped killing protected core/HIS process PID $PROCID ($PCOMM)." >> "$LOG_FILE" 2>/dev/null || true
        exit 0
    fi

    # Verified Kill Safeguard: Prevent PID Reuse / Recycling
    if [ -n "$IMAGE" ] && [ "$IMAGE" != "null" ]; then
        EXPECTED_NAME=$(basename "$IMAGE")
        CUR_COMM=$(ps -p "$PROCID" -o comm= 2>/dev/null || true)
        CUR_EXE=$(readlink -f "/proc/$PROCID/exe" 2>/dev/null | xargs basename 2>/dev/null || true)
        if [ -n "$CUR_COMM" ] && [ "$CUR_COMM" != "$EXPECTED_NAME" ] && [ "$CUR_EXE" != "$EXPECTED_NAME" ]; then
            echo "$(date '+%Y-%m-%dT%H:%M:%S%z') kill-process.sh: Safeguard: PID $PROCID ($CUR_COMM) does not match alert executable ($EXPECTED_NAME) — suspected PID reuse. Kill aborted." >> "$LOG_FILE" 2>/dev/null || true
            exit 0
        fi
    fi

    # Pre-kill Triage & Socket Evidence Capture
    if command -v ss >/dev/null 2>&1; then
        NET_CONNS=$(ss -tnp 2>/dev/null | grep -E "pid=$PROCID," | awk '{print $5}' | tr '\n' ',' | sed 's/,$//')
        [ -n "$NET_CONNS" ] && echo "$(date '+%Y-%m-%dT%H:%M:%S%z') kill-process.sh: Triage Evidence: PID $PROCID sockets: [$NET_CONNS]" >> "$LOG_FILE" 2>/dev/null || true
    fi
    
    kill -9 "$PROCID" 2>/dev/null
    if [ $? -eq 0 ]; then
        echo "$(date '+%Y-%m-%dT%H:%M:%S%z') kill-process.sh: Killed PID $PROCID ($IMAGE $PCOMM) in response to alert." >> "$LOG_FILE" 2>/dev/null || true
    else
        echo "$(date '+%Y-%m-%dT%H:%M:%S%z') kill-process.sh: Failed to kill PID $PROCID (already exited or not found)" >> "$LOG_FILE" 2>/dev/null || true
    fi

    # Parent Process Inspection
    PPID_EXT=$(echo "$INPUT_JSON" | jq -r '.parameters.alert.data.audit.ppid // .parameters.alert.data.audit.process.ppid // .parameters.alert.data.process.ppid // .parameters.alert.data.win.eventdata.parentProcessId // empty' 2>/dev/null)
    if [ -n "$PPID_EXT" ] && [ "$PPID_EXT" != "null" ] && [ "$PPID_EXT" -gt 1 ] 2>/dev/null; then
        PNAME=$(ps -p "$PPID_EXT" -o comm= 2>/dev/null || true)
        if [[ "$PNAME" =~ $PROTECTED_HIS_REGEX ]] || [ "$PPID_EXT" -le 300 ]; then
            echo "$(date '+%Y-%m-%dT%H:%M:%S%z') kill-process.sh: Safeguard: Skipped killing parent PID $PPID_EXT ($PNAME) because it is critical." >> "$LOG_FILE" 2>/dev/null || true
        else
            kill -9 "$PPID_EXT" 2>/dev/null
            if [ $? -eq 0 ]; then
                echo "$(date '+%Y-%m-%dT%H:%M:%S%z') kill-process.sh: Killed parent PID $PPID_EXT ($PNAME) (Aggressive Response)." >> "$LOG_FILE" 2>/dev/null || true
            fi
        fi
    fi
fi
