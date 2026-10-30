#!/bin/bash
# SOC oxAlph - Active Response: isolate-host.sh (Linux server)
# Triggered by confirmed-ransomware rules (130002 / 136031 / 136035).
# Network-isolates THIS host: drops all outbound except SOC management subnet.
# Logs in Wazuh standard convention (Starting / JSON / Ended).

AR_NAME="isolate-host.sh"
LOG_FILE="/var/ossec/logs/active-responses.log"

log_line() { echo "$(date '+%Y/%m/%d %H:%M:%S') active-response/bin/${AR_NAME}: $1" >> "$LOG_FILE" 2>/dev/null || echo "$1"; }
log_start() { log_line "Starting"; }
log_end()   { log_line "Ended"; }
log_json() {
  # $1=action $2=status
  local ts; ts=$(date -u '+%Y-%m-%dT%H:%M:%S.000Z')
  log_line "{\"version\":1,\"origin\":{\"name\":\"$(hostname)\",\"module\":\"${AR_NAME}\"},\"command\":\"${1}\",\"parameters\":{\"program\":\"isolate-host\",\"status\":\"${2}\",\"timestamp\":\"${ts}\"}}"
}

# ─── Dynamic Regulator Discovery: Zero Hardcoded IPs ───
# Discovers: Local subnets, Default Gateway, Active SSH peer IPs, and Wazuh Cluster
DYNAMIC_ALLOW_IPS=()

# 1. Discover Active SSH Management Connections (Prevents Lockout)
if command -v ss >/dev/null 2>&1; then
    while IFS= read -r peer_ip; do
        [ -n "$peer_ip" ] && DYNAMIC_ALLOW_IPS+=("$peer_ip")
    done < <(ss -tn sport = :22 2>/dev/null | awk 'NR>1 {print $5}' | cut -d: -f1 | grep -vE '^(127\.|0\.0\.0\.0|::)' | sort -u)
fi
if [ -n "${SSH_CLIENT:-}" ]; then
    DYNAMIC_ALLOW_IPS+=("$(echo "$SSH_CLIENT" | awk '{print $1}')")
fi

# 2. Discover Default Gateway
GW_IP=$(ip route show default 2>/dev/null | awk '{print $3}' | head -n 1)
[ -n "$GW_IP" ] && DYNAMIC_ALLOW_IPS+=("$GW_IP")

# 3. Discover Local Interface Subnets (CIDR)
LOCAL_SUBNETS=()
while IFS= read -r cidr; do
    [ -n "$cidr" ] && LOCAL_SUBNETS+=("$cidr")
done < <(ip -o -f inet addr show 2>/dev/null | awk '{print $4}' | grep -vE '^(127\.|169\.254\.)' | sort -u)

# 4. Discover Wazuh Manager / Cluster Addresses from config (IP or Domain)
while IFS= read -r mgr; do
    if [ -n "$mgr" ]; then
        if [[ "$mgr" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
            DYNAMIC_ALLOW_IPS+=("$mgr")
        else
            while IFS= read -r rip; do
                [ -n "$rip" ] && DYNAMIC_ALLOW_IPS+=("$rip")
            done < <(getent ahostsv4 "$mgr" 2>/dev/null | awk '{print $1}' | sort -u)
        fi
    fi
done < <(grep -oP '<address>\K[^<]+' /var/ossec/etc/ossec.conf 2>/dev/null || true)

# 5. Discover DNS Nameservers — Allow only port 53 (not full access)
DNS_SERVERS=()
while IFS= read -r ns; do
    [[ -n "$ns" && "$ns" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] && DNS_SERVERS+=("$ns")
done < <(grep -hE '^nameserver' /etc/resolv.conf /run/systemd/resolve/resolv.conf /run/systemd/resolve/stub-resolv.conf 2>/dev/null | awk '{print $2}' | sort -u)

# 6. Optional Environmental Subnets (if defined)
for extra in ${SOC_SUBNETS:-}; do
    LOCAL_SUBNETS+=("$extra")
done

log_start

if ! command -v iptables >/dev/null 2>&1; then
    log_json "$ACTION" "ERROR"
    log_line "ERROR: iptables not available"
    exit 1
fi

ACTION="$1"
INPUT=""
if [ ! -t 0 ]; then
    INPUT=$(cat)
fi

if [ -n "$INPUT" ]; then
    ACTION_FROM_JSON=$(echo "$INPUT" | python3 -c "import sys, json; print(json.load(sys.stdin).get('command', ''))" 2>/dev/null || true)
    [ -n "$ACTION_FROM_JSON" ] && ACTION="$ACTION_FROM_JSON"
fi
[ -z "$ACTION" ] && ACTION="add"

# ─── Safeguard 1: Do not isolate Manager if alert originated from a remote agent ───
ALERT_AGENT_ID=$(echo "$INPUT" | python3 -c "import sys, json; print(json.load(sys.stdin).get('parameters',{}).get('alert',{}).get('agent',{}).get('id','000'))" 2>/dev/null || echo "000")
if [ "$ALERT_AGENT_ID" != "000" ] && [ -f /var/ossec/bin/wazuh-analysisd ]; then
    log_line "Safeguard: Skipped isolate-host on Manager for remote agent.id=$ALERT_AGENT_ID."
    log_end
    exit 0
fi

# ─── Safeguard 2: Never auto-isolate Tier-0 Critical Servers (HIS/DB/PACS) ───
# These hosts require Human-in-the-Loop approval via SOAR/n8n before isolation.
# Add hostnames or Agent IDs of critical servers here:
PROTECTED_HOSTNAMES="MophRh4"
PROTECTED_AGENT_IDS="001"
# PROTECTED_IPS can be added if needed: PROTECTED_IPS="192.168.0.x"

CURRENT_HOSTNAME=$(hostname 2>/dev/null || echo "unknown")
for ph in $PROTECTED_HOSTNAMES; do
    if [ "$CURRENT_HOSTNAME" = "$ph" ]; then
        log_line "Safeguard: BLOCKED isolate-host on Tier-0 critical server ($CURRENT_HOSTNAME). Requires SOC approval."
        log_json "$ACTION" "BLOCKED_TIER0"
        log_end
        exit 0
    fi
done
for pa in $PROTECTED_AGENT_IDS; do
    if [ "$ALERT_AGENT_ID" = "$pa" ]; then
        log_line "Safeguard: BLOCKED isolate-host for Tier-0 Agent ID=$ALERT_AGENT_ID ($CURRENT_HOSTNAME). Requires SOC approval."
        log_json "$ACTION" "BLOCKED_TIER0"
        log_end
        exit 0
    fi
done

# ─── Safeguard 3: Block isolation if critical daemons are running ───
CRITICAL_DAEMON_REGEX="^(mysqld|mariadb|postgres|postmaster|oracle|hisservice|his-.*)$"
for daemon_check in $(ps -eo comm= 2>/dev/null | sort -u); do
    if [[ "$daemon_check" =~ $CRITICAL_DAEMON_REGEX ]]; then
        log_line "Safeguard: BLOCKED isolate-host — critical daemon '$daemon_check' detected on $(hostname). Requires SOC approval."
        log_json "$ACTION" "BLOCKED_CRITICAL_DAEMON"
        log_end
        exit 0
    fi
done

if [ "$ACTION" = "add" ]; then
    # 1. Create or reset SOC_ISOLATE chain
    iptables -F SOC_ISOLATE 2>/dev/null || iptables -N SOC_ISOLATE 2>/dev/null

    # 2. Allow loopback for local OS services
    iptables -A SOC_ISOLATE -o lo -j ACCEPT 2>/dev/null

    # 3. Allow established connections for ongoing management sessions
    iptables -A SOC_ISOLATE -m state --state ESTABLISHED,RELATED -j ACCEPT 2>/dev/null

    # 4. Dynamically allow all discovered SSH peers, Gateways & Managers
    for ip in "${DYNAMIC_ALLOW_IPS[@]}"; do
        iptables -A SOC_ISOLATE -d "$ip" -j ACCEPT 2>/dev/null
        iptables -A SOC_ISOLATE -s "$ip" -j ACCEPT 2>/dev/null
    done

    # 4b. Allow DNS (port 53 only) to internal DNS servers — no full IP access
    for dns in "${DNS_SERVERS[@]}"; do
        iptables -A SOC_ISOLATE -d "$dns" -p udp --dport 53 -j ACCEPT 2>/dev/null
        iptables -A SOC_ISOLATE -d "$dns" -p tcp --dport 53 -j ACCEPT 2>/dev/null
        iptables -A SOC_ISOLATE -s "$dns" -p udp --sport 53 -j ACCEPT 2>/dev/null
        iptables -A SOC_ISOLATE -s "$dns" -p tcp --sport 53 -j ACCEPT 2>/dev/null
    done

    # 5. REMOVED: Local Subnet allow — intentionally blocked to prevent Lateral Movement
    # Isolated host must NOT communicate with other hosts on the same subnet.
    # Only Wazuh Manager, DNS, SSH management, and Gateway are allowed above.

    # 6. Strict Anti-Exfiltration: DROP all remaining outbound & forwarded packets
    iptables -A SOC_ISOLATE -j DROP

    # Attach to OUTPUT and FORWARD chains
    iptables -D OUTPUT -j SOC_ISOLATE 2>/dev/null || true
    iptables -I OUTPUT 1 -j SOC_ISOLATE 2>/dev/null
    iptables -D FORWARD -j SOC_ISOLATE 2>/dev/null || true
    iptables -I FORWARD 1 -j SOC_ISOLATE 2>/dev/null

    # 7. Forcibly close external sockets not belonging to management IPs or local networks
    if command -v ss >/dev/null 2>&1; then
        SS_FILTER="not dst 127.0.0.1/8"
        for net in "${LOCAL_SUBNETS[@]}"; do
            SS_FILTER="$SS_FILTER and not dst $net"
        done
        for ip in "${DYNAMIC_ALLOW_IPS[@]}"; do
            SS_FILTER="$SS_FILTER and not dst $ip"
        done
        ss -K -t "$SS_FILTER" 2>/dev/null || true
    fi

    log_json "$ACTION" "ISOLATED"
    log_line "ISOLATED: Dynamic Regulator containment activated. Allowed Management IPs: [${DYNAMIC_ALLOW_IPS[*]}], DNS (port 53 only): [${DNS_SERVERS[*]}]. Local subnet access BLOCKED (anti-lateral-movement)."
elif [ "$ACTION" = "delete" ]; then
    # un-isolate: flush chain and detach
    iptables -D OUTPUT -j SOC_ISOLATE 2>/dev/null || true
    iptables -D FORWARD -j SOC_ISOLATE 2>/dev/null || true
    iptables -F SOC_ISOLATE 2>/dev/null || true
    iptables -X SOC_ISOLATE 2>/dev/null || true
    log_json "$ACTION" "RESTORED"
    log_line "RESTORED: isolation removed, full network connectivity restored."
fi

log_end
exit 0
