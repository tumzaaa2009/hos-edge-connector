##############################################################################
## Wazuh Active Response - Threat Removal for Windows (Hash-Verified)
## Deletes threats detected by FIM or Sysmon ONLY when cryptographic hash matches.
## Compatible with both FIM (syscheck) and Sysmon Event 1, 11, 15, 26, 29.
## Logs: "Successfully removed threat <path>" (Rule 120022 / 120033)
##       "Error removing threat <path>" (Rule 120023 / 120034)
##############################################################################

$ErrorActionPreference = "SilentlyContinue"

$Global:ARLogPath = "C:\Program Files (x86)\ossec-agent\active-response\active-responses.log"

function Write-ARLog($msg) {
    try {
        $timestamp = Get-Date -Format 'yyyy/MM/dd HH:mm:ss'
        $logLine = "$timestamp active-response/bin/windows-remove-malicious.cmd: $msg"

        $candidatePaths = @(
            $Global:ARLogPath,
            "C:\Program Files (x86)\ossec-agent\active-response\active-responses.log",
            (Join-Path $PSScriptRoot "..\active-response\active-responses.log"),
            (Join-Path $PSScriptRoot "..\active-responses.log"),
            (Join-Path $PSScriptRoot "active-responses.log")
        )

        foreach ($p in $candidatePaths) {
            if (-not $p) { continue }
            try {
                $dir = [System.IO.Path]::GetDirectoryName($p)
                if ($dir -and -not (Test-Path -LiteralPath $dir)) {
                    New-Item -ItemType Directory -Force -Path $dir | Out-Null
                }

                # Use FileShare.ReadWrite so we can write even if wazuh-agent has the file open
                $stream = [System.IO.File]::Open($p, [System.IO.FileMode]::Append, [System.IO.FileAccess]::Write, [System.IO.FileShare]::ReadWrite)
                $writer = New-Object System.IO.StreamWriter($stream, [System.Text.Encoding]::UTF8)
                $writer.WriteLine($logLine)
                $writer.Flush()
                $writer.Close()
                $stream.Close()
                break
            } catch {}
        }

        # 2. Write to Windows Application Event Log (picked up natively by Wazuh eventchannel)
        try {
            if (-not [System.Diagnostics.EventLog]::SourceExists("Wazuh-ActiveResponse")) {
                [System.Diagnostics.EventLog]::CreateEventSource("Wazuh-ActiveResponse", "Application")
            }
            [System.Diagnostics.EventLog]::WriteEntry("Wazuh-ActiveResponse", $logLine, [System.Diagnostics.EventLogEntryType]::Information, 12002)
        } catch {}
    } catch {}
}

# ─── 1. Read JSON from STDIN / Arguments / Pipeline ─────────────────────────
$inputJson = $null

try {
    $pipeInput = @($input)
    if ($pipeInput.Count -gt 0) {
        $inputJson = $pipeInput -join "`n"
    }
} catch {}

if ([string]::IsNullOrWhiteSpace($inputJson)) {
    try {
        $stdin = [Console]::In
        $inputJson = $stdin.ReadToEnd()
    } catch {}
}

if ([string]::IsNullOrWhiteSpace($inputJson)) {
    try {
        $inputJson = [Console]::In.ReadLine()
    } catch {}
}

if ([string]::IsNullOrWhiteSpace($inputJson)) {
    if ($args.Count -gt 0) {
        $inputJson = $args[0]
    }
}

if ([string]::IsNullOrWhiteSpace($inputJson)) {
    Write-ARLog "Error: No input JSON received from Wazuh."
    exit 0
}

try {
    $data = $inputJson | ConvertFrom-Json
    if ($data -is [string]) {
        $data = $data | ConvertFrom-Json
    }
} catch {
    Write-ARLog "Error parsing JSON payload: $_"
    exit 0
}

# Normalize alert object (handles AR wrapper, OpenSearch _source, and direct alert formats)
$alert = if ($data.parameters.alert) {
    $data.parameters.alert
} elseif ($data._source) {
    $data._source
} else {
    $data
}

# ─── 2. Extract Target File Path from Alert Payload ────────────────────────
$targetPath = $null

# Priority 1: FIM Syscheck
if ($alert.syscheck.path) {
    $targetPath = $alert.syscheck.path
}
elseif ($alert.syscheck.file) {
    $targetPath = $alert.syscheck.file
}
elseif ($alert.file) {
    $targetPath = $alert.file
}
# Priority 2: Sysmon Event 11, 15, 26, 29 (targetFilename)
elseif ($alert.data.win.eventdata.targetFilename) {
    $targetPath = $alert.data.win.eventdata.targetFilename
}
elseif ($alert.data.win.eventdata.TargetFilename) {
    $targetPath = $alert.data.win.eventdata.TargetFilename
}
# Priority 3: Sysmon Event 1 Process Create (image)
elseif ($alert.data.win.eventdata.image) {
    $targetPath = $alert.data.win.eventdata.image
}
elseif ($alert.data.win.eventdata.Image) {
    $targetPath = $alert.data.win.eventdata.Image
}
# Priority 4: extra_args
elseif ($data.parameters.extra_args -and $data.parameters.extra_args.Count -gt 0) {
    $targetPath = $data.parameters.extra_args[0]
}

if ([string]::IsNullOrWhiteSpace($targetPath)) {
    Write-ARLog "No target file path found in alert payload. Skipping."
    exit 0
}

# Normalize multiple backslashes (e.g. C:\\Users\\... -> C:\Users\...)
$targetPath = [System.Text.RegularExpressions.Regex]::Replace($targetPath, '(?<!^)\\{2,}', '\')

# Strip ADS (Alternate Data Stream) suffix like :Zone.Identifier
if ($targetPath -match '^(.*?):[a-zA-Z0-9_\.]+$') {
    $targetPath = $matches[1]
}

# Clean surrounding quotes and whitespace
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

# ─── Safety Guard: Never delete core OS binaries or critical system paths ────
if ($targetPath -match '(?i)^[a-z]:\\windows\\(system32|syswow64|winsxs)\\') {
    Write-ARLog "CRITICAL SAFETY GUARD: Refusing to delete protected system file: $targetPath"
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
$hashMatched = $false
$threatLabel = "Malicious IOC"

$ruleId = [string]$alert.rule.id
$ruleGroups = @($alert.rule.groups)
$confirmedHashRules = @('100055', '100056', '100057', '100300', '100301', '100304', '100305', '100306', '100307', '120021', '120024', '120025', '120064', '180030', '180031')
$parsedRuleId = 0
[int]::TryParse($ruleId, [ref]$parsedRuleId) | Out-Null

# Priority 4.1 Fast-Path: Did the alert originate from a confirmed hash rule on Wazuh Manager?
if ($ruleId -in $confirmedHashRules -or ($parsedRuleId -ge 180000 -and $parsedRuleId -le 189999) -or ($ruleGroups -contains 'misp_sysmon_hash_match') -or ($ruleGroups -contains 'misp_fim_hash_match')) {
    $hashMatched = $true
    $threatLabel = "MISP IOC Hash Match (Rule $ruleId)"
}

# Priority 4.2: Alert Hashes string match (Supports both Sysmon hashes and hash field)
if (-not $hashMatched) {
    $alertHashes = [string]$alert.data.win.eventdata.hashes
    if ([string]::IsNullOrWhiteSpace($alertHashes)) {
        $alertHashes = [string]$alert.data.win.eventdata.hash
    }
    if ($alertHashes -and ($alertHashes.ToLower() -match $computedSha256 -or $alertHashes.ToLower() -match $computedMd5)) {
        $hashMatched = $true
        $threatLabel = "Alert Hashes Match ($computedSha256)"
    }
}

# Priority 4.3 Fallback: Streaming check in misp_hash.txt if not matched above
if (-not $hashMatched) {
    $mispCandidates = @(
        "$env:ProgramFiles(x86)\ossec-agent\shared\misp_hash.txt",
        "$env:ProgramFiles\ossec-agent\shared\misp_hash.txt",
        "$env:ProgramData\ossec-agent\shared\misp_hash.txt",
        "C:\Program Files (x86)\ossec-agent\shared\misp_hash.txt",
        (Join-Path (Split-Path $PSScriptRoot -Parent) "shared\misp_hash.txt"),
        (Join-Path (Split-Path (Split-Path $PSScriptRoot -Parent) -Parent) "shared\misp_hash.txt"),
        (Join-Path $PSScriptRoot "misp_hash.txt")
    )
    $mispFile = $mispCandidates | Where-Object { Test-Path -LiteralPath $_ } | Select-Object -First 1

    if ($mispFile) {
        try {
            foreach ($line in [System.IO.File]::ReadLines($mispFile)) {
                $trimmed = $line.Trim().ToLower()
                if ($trimmed.StartsWith($computedSha256) -or $trimmed.StartsWith($computedMd5)) {
                    $hashMatched = $true
                    $threatLabel = $line
                    break
                }
            }
        } catch {
            Write-ARLog "Error reading misp_hash.txt: $_"
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
    $runningProcs = Get-Process | Where-Object {
        try {
            ($_.Path -and $_.Path.ToLower() -eq $targetPath.ToLower())
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
