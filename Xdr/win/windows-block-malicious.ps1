################################
## Script to remove malicious for detection IOC in MISP
## Fixed: Inbound/Outbound Firewall block, Private IP & Whitelist, Host URL parse
################################

$ErrorActionPreference = "SilentlyContinue"

function IsPrivateIP {
    param([string]$ipAddress)
    $ip = $null
    if (-not [System.Net.IPAddress]::TryParse($ipAddress, [ref]$ip)) { return $false }
    if ($ip.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetworkV6) {
        if ($ip.IsIPv6LinkLocal -or $ip.IsIPv6SiteLocal -or [System.Net.IPAddress]::IsLoopback($ip)) { return $true }
        $bytes = $ip.GetAddressBytes()
        if (($bytes[0] -band 0xFE) -eq 0xFC) { return $true }
        return $false
    }
    $bytes = $ip.GetAddressBytes()
    if ($bytes[0] -eq 10) { return $true }
    if ($bytes[0] -eq 172 -and ($bytes[1] -ge 16 -and $bytes[1] -le 31)) { return $true }
    if ($bytes[0] -eq 192 -and $bytes[1] -eq 168) { return $true }
    if ($bytes[0] -eq 127) { return $true }
    if ($bytes[0] -eq 169 -and $bytes[1] -eq 254) { return $true }
    if ($bytes[0] -eq 0 -or ($bytes[0] -eq 255 -and $bytes[1] -eq 255 -and $bytes[2] -eq 255 -and $bytes[3] -eq 255)) { return $true }
    return $false
}

function IsDomainWhitelisted {
    param([string]$domain)
    $whitelist = @('localhost', 'wazuh.com', 'microsoft.com', 'windowsupdate.com')
    return ($domain.Trim().ToLower() -in $whitelist)
}

$INPUT_JSON = [Console]::In.ReadLine()
if ([string]::IsNullOrWhiteSpace($INPUT_JSON)) {
    $INPUT_JSON = Read-Host
}
if ([string]::IsNullOrWhiteSpace($INPUT_JSON)) {
    exit 0
}

try {
    $INPUT_ARRAY = $INPUT_JSON | ConvertFrom-Json
    if ($INPUT_ARRAY -is [string]) {
        $INPUT_ARRAY = $INPUT_ARRAY | ConvertFrom-Json
    }
} catch {
    exit 0
}

$logFile = "C:\Program Files (x86)\ossec-agent\active-response\active-responses.log"
$command = $INPUT_ARRAY."command"

$localIPs = @()
try {
    $localIPs = (Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue).IPAddress
} catch {}
$hostip = (Get-WmiObject -Class Win32_NetworkAdapterConfiguration |
    Where-Object { $_.DHCPEnabled -ne $null -and $_.DefaultIPGateway -ne $null }
).IPAddress | Select-Object -First 1

$ipWhitelist = @('127.0.0.1', '::1', '0.0.0.0') + $localIPs
if ($hostip) { $ipWhitelist += $hostip }

# ─── ดึงข้อมูลจาก MISP integration path ────────────────────────────────────
$mispType = $INPUT_ARRAY."parameters"."alert"."data"."misp"."type"
$mispValue = $INPUT_ARRAY."parameters"."alert"."data"."misp"."value"
$mispDescription = $INPUT_ARRAY."parameters"."alert"."data"."misp"."source"."description"

# ─── fallback: Sysmon raw event path (กรณี alert มาจาก Sysmon โดยตรง) ─────
$sysmonEventID = $INPUT_ARRAY."parameters"."alert"."data"."win"."system"."eventID"
$sysmonDestIP = $INPUT_ARRAY."parameters"."alert"."data"."win"."eventdata"."destinationIp"
$sysmonQueryName = $INPUT_ARRAY."parameters"."alert"."data"."win"."eventdata"."queryName"


# ─── ตัดสินใจว่าจะใช้ path ไหน ─────────────────────────────────────────────
# ถ้ามี MISP data ให้ใช้ MISP path ก่อนเสมอ
if ($mispType -and $mispValue) {

    # แปลง description → event type เพื่อ route ไป block method ที่ถูกต้อง
    if ($mispDescription -match 'Event\s+(\d+)') {
        $detectedEventID = $matches[1]
    }
    else {
        $detectedEventID = if ($mispType -eq 'domain') { '22' } else { '3' }
    }

    $IOCtype = $mispType
    $IOCvalue = $mispValue
    $IOCeventid = $detectedEventID

}
elseif ($sysmonEventID) {
    # ใช้ Sysmon raw path แทน
    $IOCeventid = $sysmonEventID
    $IOCvalue = $sysmonDestIP
    $IOCtype = if ($sysmonEventID -eq '3') { 'ip-dst' } else { 'domain' }
    if ($sysmonEventID -eq '22') { $IOCvalue = $sysmonQueryName }

}
else {
    # ไม่พบข้อมูล IOC เลย → log แล้วออก
    "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') - ERROR: No IOC data found in alert" |
    Out-File -FilePath $logFile -Append -Encoding ascii
    exit 1
}

# ─── Block logic: ใช้ misp.type เป็นตัวตัดสินหลัก ──────────────────────

# ip-dst, ip-src, ip → block Inbound & Outbound via Firewall
if ($IOCtype -in @('ip-dst', 'ip-src', 'ip')) {
    foreach ($ip in $IOCvalue) {
        $ip = $ip.Trim()
        if ([string]::IsNullOrWhiteSpace($ip)) { continue }

        if ($ip -in $ipWhitelist -or (IsPrivateIP -ipAddress $ip)) {
            "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') - SKIPPED (whitelist/private): $ip" |
            Out-File -FilePath $logFile -Append -Encoding ascii
            continue
        }

        $outRule = "Wazuh Active Response - Block Outbound - $ip"
        $inRule  = "Wazuh Active Response - Block Inbound - $ip"
        $existingOut = Get-NetFirewallRule -DisplayName $outRule -ErrorAction SilentlyContinue
        $existingIn  = Get-NetFirewallRule -DisplayName $inRule -ErrorAction SilentlyContinue

        if ($command -eq 'add') {
            if (-not $existingOut) {
                New-NetFirewallRule -DisplayName $outRule `
                    -Direction Outbound -LocalPort Any -Protocol Any `
                    -Action Block -RemoteAddress $ip
            }
            if (-not $existingIn) {
                New-NetFirewallRule -DisplayName $inRule `
                    -Direction Inbound -LocalPort Any -Protocol Any `
                    -Action Block -RemoteAddress $ip
            }
            "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') - BLOCKED IP: $ip (Inbound/Outbound) via Windows Firewall" |
            Out-File -FilePath $logFile -Append -Encoding ascii

        }
        elseif ($command -eq 'delete') {
            if ($existingOut) { Remove-NetFirewallRule -DisplayName $outRule }
            if ($existingIn)  { Remove-NetFirewallRule -DisplayName $inRule }
            "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') - UNBLOCKED IP: $ip from Windows Firewall" |
            Out-File -FilePath $logFile -Append -Encoding ascii
        }
    }

}
# domain, hostname, url → block via hosts file
elseif ($IOCtype -in @('domain', 'hostname', 'url')) {

    $hostsPath = "C:\Windows\System32\drivers\etc\hosts"
    $targetDomain = $IOCvalue.Trim()
    if ($IOCtype -eq 'url') {
        try {
            $uri = [System.Uri]$targetDomain
            $targetDomain = $uri.Host
        } catch {
            $targetDomain = ($targetDomain -replace '^https?://', '') -replace '/.*$', ''
        }
    }
    $escapedVal = [regex]::Escape($targetDomain)

    if (IsDomainWhitelisted -domain $targetDomain) {
        "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') - SKIPPED (domain whitelist): $targetDomain" |
        Out-File -FilePath $logFile -Append -Encoding ascii
        exit 0
    }

    if ($command -eq 'add') {
        if (-not (Select-String -Path $hostsPath -Pattern "^127\.0\.0\.1`t$escapedVal$" -Quiet)) {
            Add-Content -Path $hostsPath -Value "127.0.0.1`t$targetDomain"
            "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') - BLOCKED DOMAIN: $targetDomain → 127.0.0.1" |
            Out-File -FilePath $logFile -Append -Encoding ascii
        }
        else {
            "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') - SKIP: $targetDomain already blocked" |
            Out-File -FilePath $logFile -Append -Encoding ascii
        }

    }
    elseif ($command -eq 'delete') {
        $content = Get-Content -Path $hostsPath
        $filtered = $content | Where-Object { $_ -notmatch "^127\.0\.0\.1`t$escapedVal$" }
        $filtered | Set-Content -Path $hostsPath
        "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') - UNBLOCKED DOMAIN: $targetDomain" |
        Out-File -FilePath $logFile -Append -Encoding ascii
    }

}
else {
    "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') - UNHANDLED IOC type: $IOCtype value: $IOCvalue" |
    Out-File -FilePath $logFile -Append -Encoding ascii
}
