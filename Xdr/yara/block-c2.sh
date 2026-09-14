#!/bin/bash
# SOC oxAlph - Active Response: block-c2.sh (Linux server / Linux client)
# Triggered by Wazuh rules 136001-136101 (soc_c2_rules.xml).
# Blocks the C2 destination IP IMMEDIATELY (iptables) - "stop before it works".
# Wazuh passes: $1=action(add/delete), $2=user, $3=srcip, and full alert JSON on stdin.
# We prefer the DESTINATION IP (C2 server) over srcip for outbound C2 blocking.

AR_NAME="block-c2.sh"
LOG_FILE="/var/ossec/logs/active-responses.log"

log_line() { echo "$(date '+%Y/%m/%d %H:%M:%S') active-response/bin/${AR_NAME}: $1" >> "$LOG_FILE" 2>/dev/null || echo "$1"; }
log_start() { log_line "Starting"; }
log_end()   { log_line "Ended"; }
log_json() {
  # $1=action(add/delete) $2=blocked_ip $3=rule_id $4=status(BLOCKED/UNBLOCKED/SKIP/DUPLICATE/ERROR)
  local ts; ts=$(date -u '+%Y-%m-%dT%H:%M:%S.000Z')
  log_line "{\"version\":1,\"origin\":{\"name\":\"$(hostname)\",\"module\":\"${AR_NAME}\"},\"command\":\"${1}\",\"parameters\":{\"program\":\"soc-block-c2\",\"blocked_ip\":\"${2}\",\"rule\":\"${3}\",\"status\":\"${4}\",\"timestamp\":\"${ts}\"}}"
}

# --- read alert JSON from stdin (robust: jq -> python3 -> grep fallback) ---
ALERT=""
if [ ! -t 0 ]; then
  read -r -t 2 ALERT
fi
extract() {
  local key="$1" val=""
  if command -v jq >/dev/null 2>&1; then
    val=$(echo "$ALERT" | jq -r --arg k "$key" '
      def cands: if $k=="srcip" then ["srcip","src_ip"]
                 elif $k=="dstip" then ["dstip","dest_ip","dst_ip"]
                 elif $k=="rule"  then ["rule","rule_id"]
                 else [$k] end;
      first(cands[] as $c
            | (.parameters.alert[$c]
               // .parameters.alert.data[$c]
               // empty)
            | if $k=="rule" and (type=="object") then .id else . end)
      // empty' 2>/dev/null | head -1)
  elif command -v python3 >/dev/null 2>&1; then
    val=$(echo "$ALERT" | python3 -c "
import sys, json
try:
    a=json.load(sys.stdin).get('parameters',{}).get('alert',{})
    aliases={'srcip':['srcip','src_ip'],'dstip':['dstip','dest_ip','dst_ip'],'rule':['rule','rule_id']}.get('$key',['$key'])
    v=''
    for kk in aliases:
        x=a.get(kk) or a.get('data',{}).get(kk)
        if x:
            v = x.get('id','') if isinstance(x,dict) else x
            break
    print(v if v else '')
except Exception: print('')
" 2>/dev/null)
  else
    val=$(echo "$ALERT" | grep -o "\"$key\":\s*\"[^\"]*\"" | head -1 | cut -d'"' -f4)
  fi
  echo "$val"
}

SRCIP=$(extract srcip)
[ -z "$SRCIP" ] && SRCIP="${3:-}"
DSTIP=$(extract dstip)
RULEID=$(extract rule)
[ -z "$RULEID" ] && RULEID="AR_DROP"
ACTION=${1:-add}
log_start

is_public() { python3 - "$1" <<'PYEOF' 2>/dev/null || echo 0
import sys, ipaddress
try:
    ip = ipaddress.ip_address(sys.argv[1])
    # private/loopback/link-local only. TEST-NET ranges (192.0.2.0/24,
    # 198.51.100.0/24, 203.0.113.0/24) are treated as BLOCKABLE so that
    # lab/C2 simulations work correctly.
    blocked_internal = (ip.is_loopback or ip.is_link_local or
                        ip in ipaddress.ip_network('10.0.0.0/8') or
                        ip in ipaddress.ip_network('172.16.0.0/12') or
                        ip in ipaddress.ip_network('192.168.0.0/16') or
                        ip in ipaddress.ip_network('169.254.0.0/16'))
    print(0 if blocked_internal else 1)
except Exception:
    print(0)
PYEOF
}

# Choose blocking target: prefer external C2 destination; fallback to public srcip
BLOCKIP=""
if [ -n "$DSTIP" ] && [ "$DSTIP" != "null" ] && [ "$(is_public "$DSTIP")" = "1" ]; then
  BLOCKIP="$DSTIP"        # external C2 server
elif [ -n "$SRCIP" ] && [ "$SRCIP" != "null" ] && [ "$(is_public "$SRCIP")" = "1" ]; then
  BLOCKIP="$SRCIP"        # external C2 source IP
fi

[ -z "$BLOCKIP" ] && { log_json "${ACTION}" "none" "${RULEID}" "SKIP"; log_end; exit 0; }

# --- Dynamic Regulator Safeguard: Never block current SSH peers, Gateway, Local IPs, or DNS ---
REGULATOR_SAFE_IPS=()
[ -n "${SSH_CLIENT:-}" ] && REGULATOR_SAFE_IPS+=("$(echo "$SSH_CLIENT" | awk '{print $1}')")
GW_IP=$(ip route show default 2>/dev/null | awk '{print $3}' | head -n 1)
[ -n "$GW_IP" ] && REGULATOR_SAFE_IPS+=("$GW_IP")
while IFS= read -r if_ip; do
    [ -n "$if_ip" ] && REGULATOR_SAFE_IPS+=("$if_ip")
done < <(ip -o -f inet addr show 2>/dev/null | awk '{print $4}' | cut -d/ -f1)
if command -v ss >/dev/null 2>&1; then
    while IFS= read -r p; do
        [ -n "$p" ] && REGULATOR_SAFE_IPS+=("$p")
    done < <(ss -tn sport = :22 2>/dev/null | awk 'NR>1 {print $5}' | cut -d: -f1 | grep -vE '^(127\.|0\.0\.0\.0|::)' | sort -u)
fi
while IFS= read -r ns; do
    [[ -n "$ns" && "$ns" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] && REGULATOR_SAFE_IPS+=("$ns")
done < <(grep -E '^nameserver' /etc/resolv.conf 2>/dev/null | awk '{print $2}' | sort -u)

# Discover Wazuh Manager / Cluster to prevent accidental C2 block
while IFS= read -r mgr; do
    if [ -n "$mgr" ]; then
        if [[ "$mgr" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
            REGULATOR_SAFE_IPS+=("$mgr")
        else
            while IFS= read -r rip; do
                [ -n "$rip" ] && REGULATOR_SAFE_IPS+=("$rip")
            done < <(getent ahostsv4 "$mgr" 2>/dev/null | awk '{print $1}' | sort -u)
        fi
    fi
done < <(grep -oP '<address>\K[^<]+' /var/ossec/etc/ossec.conf 2>/dev/null || true)

for safe_ip in "${REGULATOR_SAFE_IPS[@]}"; do
    if [ "$BLOCKIP" = "$safe_ip" ]; then
        log_json "${ACTION}" "${BLOCKIP}" "${RULEID}" "SKIP_REGULATOR_SAFEGUARD"
        log_line "Regulator Safeguard: Target $BLOCKIP is protected Regulator infrastructure (SSH/GW/DNS/Local). Block skipped."
        log_end
        exit 0
    fi
done

# --- duplicate guard: skip if already blocked ---
if [ "$ACTION" = "add" ] && command -v iptables >/dev/null 2>&1; then
  if iptables -C OUTPUT -d "$BLOCKIP" -j DROP 2>/dev/null; then
    log_json "${ACTION}" "${BLOCKIP}" "${RULEID}" "DUPLICATE"
    log_end
    exit 0
  fi
fi

# --- apply firewall block (iptables -> nftables fallback) ---
if command -v iptables >/dev/null 2>&1; then
  if [ "$ACTION" = "add" ]; then
    iptables -I INPUT   -s "$BLOCKIP" -j DROP 2>/dev/null
    iptables -I OUTPUT  -d "$BLOCKIP" -j DROP 2>/dev/null
    iptables -I FORWARD -d "$BLOCKIP" -j DROP 2>/dev/null
    log_json "${ACTION}" "${BLOCKIP}" "${RULEID}" "BLOCKED"
  else
    iptables -D INPUT   -s "$BLOCKIP" -j DROP 2>/dev/null
    iptables -D OUTPUT  -d "$BLOCKIP" -j DROP 2>/dev/null
    iptables -D FORWARD -d "$BLOCKIP" -j DROP 2>/dev/null
    log_json "${ACTION}" "${BLOCKIP}" "${RULEID}" "UNBLOCKED"
  fi
elif command -v nft >/dev/null 2>&1; then
  nft add table inet soc_block 2>/dev/null
  nft add chain inet soc_block output '{ type filter hook output priority -150; }' 2>/dev/null
  if [ "$ACTION" = "add" ]; then
    nft add rule inet soc_block output ip daddr "$BLOCKIP" drop
    log_json "${ACTION}" "${BLOCKIP}" "${RULEID}" "BLOCKED"
  else
    log_json "delete" "${BLOCKIP}" "${RULEID}" "ERROR"
  fi
else
  log_json "${ACTION}" "${BLOCKIP}" "${RULEID}" "ERROR"
  log_end
  exit 1
fi

log_end
exit 0
