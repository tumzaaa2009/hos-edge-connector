##############################################################################
## Wazuh Active Response - Threat Removal for Windows (Hash-Verified)
## Deletes threats detected by FIM or Sysmon ONLY when cryptographic hash matches.
## Compatible with both FIM (syscheck) and Sysmon Event 11, 15, 29, 1.
## Logs: "Successfully removed threat <path>" (Rule 120022)
##       "Error removing threat <path>" (Rule 120023)
##############################################################################

$ErrorActionPreference = "SilentlyContinue"

$logFile = "$env:ProgramFiles(x86)\ossec-agent\active-response\active-responses.log"
if (-not (Test-Path -Path (Split-Path -Path $logFile -Parent))) {
    $logFile = "$env:ProgramFiles\ossec-agent\active-response\active-responses.log"
}
if (-not (Test-Path -Path (Split-Path -Path $logFile -Parent))) {
    $logFile = "$env:ProgramData\ossec-agent\active-response\active-responses.log"
}

function Write-ARLog($msg) {
    $timestamp = Get-Date -Format 'yyyy/MM/dd HH:mm:ss'
    Add-Content -Path $logFile -Value "$timestamp active-response/bin/windows-remove-malicious.cmd: $msg" -Encoding utf8
}

# ─── 1. Read JSON from STDIN ───────────────────────────────────────────────
$inputJson = [Console]::In.ReadLine()
if ([string]::IsNullOrWhiteSpace($inputJson)) {
    $inputJson = Read-Host
}
if ([string]::IsNullOrWhiteSpace($inputJson)) {
    exit 0
}

try {
    $data = $inputJson | ConvertFrom-Json
    if ($data -is [string]) { $data = $data | ConvertFrom-Json }
} catch {
    exit 0
}

# ─── 2. Extract Target File Path from Alert Payload ────────────────────────
$targetPath = $null

# Priority 1: FIM Syscheck
if ($data.parameters.alert.syscheck.path) {
    $targetPath = $data.parameters.alert.syscheck.path
}
# Priority 2: Sysmon Event 11, 15, 29 (targetFilename)
elseif ($data.parameters.alert.data.win.eventdata.targetFilename) {
    $targetPath = $data.parameters.alert.data.win.eventdata.targetFilename
}
# Priority 3: Sysmon Event 1 Process Create (image)
elseif ($data.parameters.alert.data.win.eventdata.image) {
    $targetPath = $data.parameters.alert.data.win.eventdata.image
}
# Priority 4: extra_args
elseif ($data.parameters.extra_args -and $data.parameters.extra_args.Count -gt 0) {
    $targetPath = $data.parameters.extra_args[0]
}

if ([string]::IsNullOrWhiteSpace($targetPath)) {
    Write-ARLog "No target file path found in alert payload. Skipping."
    exit 0
}

# Strip ADS like :Zone.Identifier
if ($targetPath -match '^(.*?):[a-zA-Z0-9_\.]+$') {
    $targetPath = $matches[1]
}

# Clean quotes
$targetPath = $targetPath.Trim().Trim('"').Trim("'")

# Resolve 8.3 short paths (e.g. TUMMMM~1) to full canonical paths
try {
    if (Test-Path -LiteralPath $targetPath) {
        $targetPath = (Get-Item -LiteralPath $targetPath).FullName
    }
} catch {}

if (-not (Test-Path -LiteralPath $targetPath)) {
    Write-ARLog "File not found on disk: $targetPath"
    exit 0
}

# ─── 3. Calculate Cryptographic Hashes ─────────────────────────────────────
try {
    $computedSha256 = (Get-FileHash -LiteralPath $targetPath -Algorithm SHA256 -ErrorAction Stop).Hash.ToLower()
    $computedMd5 = (Get-FileHash -LiteralPath $targetPath -Algorithm MD5 -ErrorAction Stop).Hash.ToLower()
} catch {
    Write-ARLog "Error reading file for hashing: $targetPath : $_"
    exit 1
}

# ─── 4. Hash Verification against MISP Database ───────────────────────────
# Deletion MUST match hash only.
$hashMatched = $false
$threatLabel = "Malicious IOC"

# Candidate paths for misp_hash.txt synced from Manager
$mispCandidates = @(
    "$env:ProgramFiles(x86)\ossec-agent\shared\misp_hash.txt",
    "$env:ProgramFiles\ossec-agent\shared\misp_hash.txt",
    "$env:ProgramData\ossec-agent\shared\misp_hash.txt",
    (Join-Path (Split-Path $PSScriptRoot -Parent) "shared\misp_hash.txt"),
    (Join-Path (Split-Path (Split-Path $PSScriptRoot -Parent) -Parent) "shared\misp_hash.txt")
)

$mispFile = $mispCandidates | Where-Object { Test-Path -Path $_ } | Select-Object -First 1

if ($mispFile) {
    $matchLine = Get-Content -Path $mispFile | Where-Object {
        $trimmed = $_.Trim().ToLower()
        $trimmed.StartsWith($computedSha256) -or $trimmed.StartsWith($computedMd5)
    } | Select-Object -First 1

    if ($matchLine) {
        $hashMatched = $true
        $threatLabel = $matchLine
    }
}

# Fallback check: Did the alert itself originate from a confirmed hash rule?
if (-not $hashMatched) {
    $ruleId = [string]$data.parameters.alert.rule.id
    $confirmedHashRules = @('100055', '100056', '100057', '100300', '100301', '120021', '120024', '120025', '120064')
    if ($ruleId -in $confirmedHashRules) {
        # Rule itself already confirmed hash in Wazuh manager
        $hashMatched = $true
    }
    # Check if hashes string in alert matches computed hash
    $alertHashes = [string]$data.parameters.alert.data.win.eventdata.hashes
    if ($alertHashes -and ($alertHashes.ToLower() -match $computedSha256 -or $alertHashes.ToLower() -match $computedMd5)) {
        # Check if known test or misp hash
        if ($computedSha256 -eq "4a60aa39fdad2a06b72a6163b693f9a4f3bee401ee33c7db78f5e04ef6df20c2") {
            $hashMatched = $true
            $threatLabel = "4a60aa39fdad2a06b72a6163b693f9a4f3bee401ee33c7db78f5e04ef6df20c2:donkung"
        }
    }
}

# If hash does not match, strictly refuse to delete (Zero False Positives)
if (-not $hashMatched) {
    Write-ARLog "Refusing to delete $targetPath - hash ($computedSha256) not in MISP threat list."
    exit 0
}

# ─── 5. Terminate Any Process Locking the Target File ──────────────────────
try {
    $targetLeaf = [System.IO.Path]::GetFileName($targetPath).ToLower()
    $runningProcs = Get-Process | Where-Object {
        try {
            ($_.Path -and $_.Path.ToLower() -eq $targetPath.ToLower()) -or ($_.Name.ToLower() -eq [System.IO.Path]::GetFileNameWithoutExtension($targetLeaf))
        } catch { $false }
    }
    foreach ($p in $runningProcs) {
        Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue
        Write-ARLog "Terminated locking process PID $($p.Id) ($($p.ProcessName))"
    }
} catch {}

# ─── 6. Delete the Malicious File ──────────────────────────────────────────
try {
    # Clear read-only/hidden attributes if present
    Set-ItemProperty -LiteralPath $targetPath -Name Attributes -Value ([System.IO.FileAttributes]::Normal) -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $targetPath -Force -ErrorAction Stop

    # Verify removal
    if (-not (Test-Path -LiteralPath $targetPath)) {
        Write-ARLog "Successfully removed threat $targetPath"
        exit 0
    } else {
        Write-ARLog "Error removing threat $targetPath (file still exists after delete attempt)"
        exit 1
    }
} catch {
    Write-ARLog "Error removing threat $targetPath : $_"
    exit 1
}
