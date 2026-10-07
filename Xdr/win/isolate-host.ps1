# ==============================================================================
# Wazuh Active Response - Dynamic Fail-Safe Host Isolation with Auto-Revert
# - Fully dynamic: Zero hardcoded IPs or subnets
# - Dynamic Manager IP detection: Active TCP 1514 socket -> ossec.conf -> payload
# - Dynamic Local Subnet & Gateway preservation for continuous connectivity
# - 120-second Watchdog Auto-Revert to prevent remote host lockout
# - Supports "add" (isolate) and "delete" (un-isolate/rollback)
# ==============================================================================

$ErrorActionPreference = 'SilentlyContinue'

$LogDir  = 'C:\Program Files (x86)\ossec-agent\active-response'
$LogFile = Join-Path $LogDir 'active-responses.log'
$Backup  = Join-Path $LogDir 'network-backup.json'
$WatchdogPid = Join-Path $LogDir 'isolate-watchdog.pid'
$RulePrefix = 'SOC-ISOLATE'

# ---------------------------------------------------------------------------
# DYNAMIC MANAGER IP DETECTION (zero hardcoded values)
# Priority: 1) Live established TCP socket to port 1514/1515
#           2) ossec.conf <client><server><address>
#           3) AR payload isolation_config.manager_ip
#           4) Environment variable WAZUH_MANAGER_IP
# ---------------------------------------------------------------------------
function Get-DynamicManagerIP {
    try {
        $liveConn = Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue |
                    Where-Object { $_.RemotePort -in @(1514, 1515) } | Select-Object -First 1
        if ($liveConn -and $liveConn.RemoteAddress -and $liveConn.RemoteAddress -ne '127.0.0.1') {
            Write-ARLog "Dynamic Manager IP detected from live TCP socket: $($liveConn.RemoteAddress):$($liveConn.RemotePort)"
            return $liveConn.RemoteAddress
        }
    } catch { }

    $ossecConf = 'C:\Program Files (x86)\ossec-agent\ossec.conf'
    if (Test-Path $ossecConf) {
        try {
            [xml]$xml = Get-Content -LiteralPath $ossecConf -Raw
            $mgrAddr = $xml.ossec_config.client.server.address
            if ($mgrAddr -and $mgrAddr.Trim()) {
                try {
                    $resolved = [System.Net.Dns]::GetHostAddresses($mgrAddr) |
                                Where-Object { $_.AddressFamily -eq 'InterNetwork' } | Select-Object -First 1
                    if ($resolved) {
                        Write-ARLog "Dynamic Manager IP resolved from ossec.conf: $($resolved.IPAddressToString) (config: $mgrAddr)"
                        return $resolved.IPAddressToString
                    }
                } catch { }
                Write-ARLog "Dynamic Manager IP from ossec.conf: $mgrAddr"
                return $mgrAddr
            }
        } catch { }
    }

    if ($env:WAZUH_MANAGER_IP) {
        Write-ARLog "Dynamic Manager IP from WAZUH_MANAGER_IP env: $env:WAZUH_MANAGER_IP"
        return $env:WAZUH_MANAGER_IP
    }

    return $null
}

# ---------------------------------------------------------------------------
# DYNAMIC LOCAL SUBNET DETECTION (preserve LAN connectivity)
# ---------------------------------------------------------------------------
function Get-DynamicLocalSubnets {
    $allowed = New-Object System.Collections.Generic.List[string]

    # Default gateways
    try {
        $routes = Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue
        foreach ($r in $routes) {
            if ($r.NextHop -and $r.NextHop -ne '0.0.0.0') {
                $allowed.Add($r.NextHop + '/32')
            }
        }
    } catch { }

    # Active IPv4 subnets (exclude loopback and link-local)
    try {
        $addrs = Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue |
                 Where-Object { $_.InterfaceAlias -notmatch 'Loopback' -and $_.IPAddress -notmatch '^169\.254\.' }
        foreach ($a in $addrs) {
            if ($a.IPAddress -and $a.PrefixLength) {
                $ipBytes = [System.Net.IPAddress]::Parse($a.IPAddress).GetAddressBytes()
                $maskVal = [uint32]0
                for ($i = 0; $i -lt $a.PrefixLength; $i++) {
                    $maskVal = $maskVal -bor ([uint32]1 -shl (31 - $i))
                }
                $maskBytes = [System.BitConverter]::GetBytes([uint32][System.Net.IPAddress]::HostToNetworkOrder([int32]$maskVal))
                $netBytes = New-Object byte[] 4
                for ($i = 0; $i -lt 4; $i++) { $netBytes[$i] = $ipBytes[$i] -band $maskBytes[$i] }
                $netStr = (New-Object System.Net.IPAddress(,$netBytes)).ToString()
                $cidr = "$netStr/$($a.PrefixLength)"
                if (-not $allowed.Contains($cidr)) { $allowed.Add($cidr) }
            }
        }
    } catch { }

    return $allowed
}

function Write-ARLog {
    param([string]$Message)
    $line = '{0} [isolate-host] {1}' -f (Get-Date -Format 'yyyy-MM-ddTHH:mm:ss.fffK'), $Message
    try { Add-Content -LiteralPath $LogFile -Value $line -Encoding ascii -ErrorAction Stop } catch { }
    Write-Output $line
}

# ---------------------------------------------------------------- read input
$rawInput = [Console]::In.ReadLine()
if ([string]::IsNullOrWhiteSpace($rawInput)) { $rawInput = Read-Host }
if ([string]::IsNullOrWhiteSpace($rawInput)) {
    Write-ARLog 'ABORT: empty AR payload received.'
    exit 1
}

try {
    $data = $rawInput | ConvertFrom-Json
    if ($data -is [string]) { $data = $data | ConvertFrom-Json }
} catch {
    Write-ARLog "ABORT: could not parse AR payload: $($_.Exception.Message)"
    exit 1
}

$command = $data.command
$ruleId  = $data.parameters.alert.rule.id

# Override from AR payload if present
$alertData = $data.parameters.alert.data
if ($alertData.isolation_config) {
    $ic = $alertData.isolation_config
    if ($ic.manager_ip) { $ManagerIP = $ic.manager_ip }
    if ($ic.manager_ports) { $ManagerPorts = @($ic.manager_ports) }
    if ($ic.allow_subnets) { $AllowSubnets = @($ic.allow_subnets) }
    if ($ic.rule_prefix) { $RulePrefix = $ic.rule_prefix }
}

# Dynamic resolution
$ManagerIP = Get-DynamicManagerIP
$ManagerPorts = @(1514, 1515)
$DynamicSubnets = Get-DynamicLocalSubnets

# =============================================================== CONTAIN =====
if ($command -eq 'add') {

    # Stop any existing watchdog process
    if (Test-Path $WatchdogPid) {
        try {
            $oldPid = Get-Content -LiteralPath $WatchdogPid -Raw -ErrorAction SilentlyContinue
            if ($oldPid -match '^\d+$') {
                Stop-Process -Id ([int]$oldPid.Trim()) -Force -ErrorAction SilentlyContinue
            }
            Remove-Item -LiteralPath $WatchdogPid -Force -ErrorAction SilentlyContinue
        } catch { }
    }

    # --- 1. Record the exact pre-isolation state (so restore is exact) ------
    $snapshot = @()
    foreach ($adapter in (Get-NetAdapter | Where-Object { $_.Hidden -ne 'True' })) {
        $cfg = $null
        try { $cfg = Get-NetIPAddress -InterfaceIndex $adapter.ifIndex -AddressFamily IPv4 -ErrorAction Stop |
                    Select-Object -First 1 } catch { }
        $gw = $null
        try { $gw = (Get-NetRoute -InterfaceIndex $adapter.ifIndex -DestinationPrefix '0.0.0.0/0' -ErrorAction Stop |
                    Select-Object -First 1).NextHop } catch { }

        $snapshot += [pscustomobject]@{
            Name                 = $adapter.Name
            InterfaceDescription= $adapter.InterfaceDescription
            IfIndex              = $adapter.ifIndex
            WasUp                = ($adapter.Status -eq 'Up')
            DHCPEnabled          = $cfg.Dhcp
            IPv4Address          = $cfg.IPAddress
            PrefixLength         = $cfg.PrefixLength
            Gateway              = $gw
        }
    }

    if ($snapshot.Count -eq 0) {
        Write-ARLog 'ABORT: no usable network adapter found - refusing to isolate (avoid un-recoverable state).'
        exit 1
    }

    $snapshot | ConvertTo-Json -Depth 4 |
        Out-File -FilePath $Backup -Encoding ascii -Force

    Write-ARLog "BACKUP written: $($snapshot.Count) adapter(s) -> $Backup"
    foreach ($a in $snapshot) {
        Write-ARLog ("  SNAP {0} (idx {1}) up={2} dhcp={3} ip={4} gw={5}" -f `
            $a.Name, $a.IfIndex, $a.WasUp, $a.DHCPEnabled, ($a.IPv4Address -join ','), $a.Gateway)
    }

    # --- 2. Idempotent rule cleanup ----------------------------------------
    Get-NetFirewallRule -DisplayName "$RulePrefix*" -ErrorAction SilentlyContinue | Remove-NetFirewallRule

    # Safe Mode flag: if set via env or payload, test rule synthesis without cutting off host network
    $isSafeMode = ($env:ISOLATE_SAFE_MODE -eq '1' -or $alertData.safe_mode -eq $true)

    if ($isSafeMode) {
        Write-ARLog 'SAFE MODE ACTIVE: Validating isolation mechanisms without dropping host network.'
        # Create verification dummy rules targeting non-routable test prefix RFC 5737 TEST-NET-2
        New-NetFirewallRule -DisplayName "$RulePrefix - Safe Test Block Inbound" `
            -Direction Inbound -Action Block -Protocol Any -LocalPort Any `
            -RemoteAddress '198.51.100.0/24' -Profile Any `
            -Description 'RH4 containment safe test: verification dummy rule' | Out-Null

        New-NetFirewallRule -DisplayName "$RulePrefix - Safe Test Block Outbound" `
            -Direction Outbound -Action Block -Protocol Any -LocalPort Any `
            -RemoteAddress '198.51.100.0/24' -Profile Any `
            -Description 'RH4 containment safe test: verification dummy rule' | Out-Null
    } else {
        # --- 3. Block ALL inbound (deny unsolicited connections) ---------------
        New-NetFirewallRule -DisplayName "$RulePrefix - Block All Inbound" `
            -Direction Inbound -Action Block -Protocol Any -LocalPort Any `
            -RemoteAddress Any -Profile Any `
            -Description 'RH4 containment: deny all unsolicited inbound traffic' | Out-Null

        # --- 4. Block ALL outbound (deny by default) ---------------------------
        New-NetFirewallRule -DisplayName "$RulePrefix - Block All Outbound" `
            -Direction Outbound -Action Block -Protocol Any -LocalPort Any `
            -RemoteAddress Any -Profile Any `
            -Description 'RH4 containment: deny all outbound by default' | Out-Null
    }

    # --- 5. ALLOW rules for Wazuh Manager (highest priority) ---------------
    if ($ManagerIP) {
        foreach ($p in $ManagerPorts) {
            New-NetFirewallRule -DisplayName "$RulePrefix - Allow Manager $p Outbound" `
                -Direction Outbound -Action Allow -Protocol TCP `
                -RemoteAddress $ManagerIP -RemotePort $p -LocalPort Any -ErrorAction SilentlyContinue | Out-Null
            New-NetFirewallRule -DisplayName "$RulePrefix - Allow Manager $p Inbound" `
                -Direction Inbound -Action Allow -Protocol TCP `
                -RemoteAddress $ManagerIP -RemotePort $p -LocalPort Any -ErrorAction SilentlyContinue | Out-Null
        }
    }

    # --- 6. ALLOW rules for dynamic local subnets and gateway --------------
    foreach ($subnet in $DynamicSubnets) {
        New-NetFirewallRule -DisplayName "$RulePrefix - Allow Subnet $subnet Outbound" `
            -Direction Outbound -Action Allow -Protocol Any `
            -RemoteAddress $subnet -LocalPort Any -ErrorAction SilentlyContinue | Out-Null
        New-NetFirewallRule -DisplayName "$RulePrefix - Allow Subnet $subnet Inbound" `
            -Direction Inbound -Action Allow -Protocol Any `
            -RemoteAddress $subnet -LocalPort Any -ErrorAction SilentlyContinue | Out-Null
    }

    # --- 6.1 ALLOW active remote management sessions (anti-lockout) -------
    try {
        $activeSessions = Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue |
            Where-Object { $_.RemoteAddress -notmatch '^(127\.|0\.0\.|::1)' -and $_.RemoteAddress -ne $ManagerIP } |
            Select-Object -ExpandProperty RemoteAddress -Unique
        foreach ($remIp in $activeSessions) {
            New-NetFirewallRule -DisplayName "$RulePrefix - Allow Session $remIp Out" `
                -Direction Outbound -Action Allow -Protocol TCP `
                -RemoteAddress $remIp -LocalPort Any -ErrorAction SilentlyContinue | Out-Null
            New-NetFirewallRule -DisplayName "$RulePrefix - Allow Session $remIp In" `
                -Direction Inbound -Action Allow -Protocol TCP `
                -RemoteAddress $remIp -LocalPort Any -ErrorAction SilentlyContinue | Out-Null
        }
    } catch { }

    Write-ARLog "ISOLATED (fail-safe): Manager=$ManagerIP Ports=$($ManagerPorts -join ',') Subnets=$($DynamicSubnets -join ',')"

    # --- 7. Start 120s Watchdog Auto-Revert timer --------------------------
    try {
        $watchdogCmd = "Start-Sleep -Seconds 120; Get-NetFirewallRule -DisplayName '$RulePrefix*' -ErrorAction SilentlyContinue | Remove-NetFirewallRule; Add-Content -LiteralPath '$LogFile' -Value '$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') isolate-host.ps1: WATCHDOG AUTO-REVERT: 120s timer expired, all $RulePrefix rules cleared.'; Remove-Item -LiteralPath '$WatchdogPid' -Force -ErrorAction SilentlyContinue"
        $proc = Start-Process -FilePath 'powershell.exe' `
            -ArgumentList ('-NoProfile', '-WindowStyle', 'Hidden', '-Command', $watchdogCmd) `
            -PassThru -WindowStyle Hidden
        if ($proc -and $proc.Id) {
            Set-Content -LiteralPath $WatchdogPid -Value $proc.Id.ToString() -Encoding ascii
            Write-ARLog "Watchdog auto-revert armed (PID: $($proc.Id), timeout: 120s)."
        }
    } catch {
        Write-ARLog "Warning: Could not start watchdog: $($_.Exception.Message)"
    }

    exit 0
}

# =============================================================== RESTORE =====
elseif ($command -eq 'delete') {

    # Stop watchdog process if running
    if (Test-Path $WatchdogPid) {
        try {
            $wPid = Get-Content -LiteralPath $WatchdogPid -Raw -ErrorAction SilentlyContinue
            if ($wPid -match '^\d+$') {
                Stop-Process -Id ([int]$wPid.Trim()) -Force -ErrorAction SilentlyContinue
            }
            Remove-Item -LiteralPath $WatchdogPid -Force -ErrorAction SilentlyContinue
        } catch { }
    }

    Get-NetFirewallRule -DisplayName "$RulePrefix*" -ErrorAction SilentlyContinue | Remove-NetFirewallRule
    Write-ARLog 'REMOVED all containment firewall rules.'

    if (Test-Path $Backup) {
        $snapshot = Get-Content -Path $Backup -Raw | ConvertFrom-Json
        foreach ($a in $snapshot) {
            if ($a.DHCPEnabled -eq 'Enabled' -or -not $a.DHCPEnabled) {
                # restore DHCP addressing exactly as it was found
                & netsh interface ip set address name="$($a.Name)" source=dhcp | Out-Null
                & netsh interface ip set dns   name="$($a.Name)" source=dhcp | Out-Null
            } else {
                & netsh interface ip set address name="$($a.Name)" source=static `
                    addr=$($a.IPv4Address) mask=$($a.PrefixLength) | Out-Null
                if ($a.Gateway) {
                    & netsh interface ip set address name="$($a.Name)" source=static `
                        addr=$($a.IPv4Address) mask=$($a.PrefixLength) gateway=$($a.Gateway) | Out-Null
                }
                & netsh interface ip set dns name="$($a.Name)" source=static addr=$($a.Gateway) | Out-Null
            }
            if ($a.WasUp) {
                Enable-NetAdapter -Name $a.Name -Confirm:$false -ErrorAction SilentlyContinue
            }
            Write-ARLog "RESTORED adapter '$($a.Name)'"
        }
        Remove-Item -Path $Backup -Force -ErrorAction SilentlyContinue
        Write-ARLog 'RESTORE complete; backup file removed.'
    } else {
        Write-ARLog 'WARN: no backup file found - falling back to DHCP on all adapters.'
        foreach ($ad in (Get-NetAdapter)) {
            & netsh interface ip set address name="$($ad.Name)" source=dhcp | Out-Null
            & netsh interface ip set dns   name="$($ad.Name)" source=dhcp | Out-Null
        }
    }

    & ipconfig /flushdns | Out-Null
    exit 0
}

else {
    Write-ARLog "SKIP: unknown command '$command'."
    exit 0
}

# =============================================================================
# MANUAL ESCAPE HATCH (console on the isolated host)
#   Run this if the host is contained and you have physical/console access:
#       powershell -ExecutionPolicy Bypass -File "C:\Program Files (x86)\ossec-agent\active-response\bin\isolate-host.ps1"
#   ...or directly:
#       Get-NetFirewallRule -DisplayName "Wazuh Isolation*" | Remove-NetFirewallRule
#       netsh interface ip set address name="Ethernet" source=dhcp
# =============================================================================
