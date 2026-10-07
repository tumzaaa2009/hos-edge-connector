# ==============================================================================
# active-response/bin/kill-process.ps1
# RH4 Central SOC - Windows Active Response : terminate offending process
#
# Design goals (see WINDOWS_RULE_TEST_CHECKLIST.md TC-08):
#   1. NEVER kill a critical / protected Windows process (anti-lockout).
#   2. NEVER kill the Wazuh agent or its own parent chain.
#   3. NEVER walk up and kill ancestor processes  <-- removed, see CHANGELOG
#   4. Fail closed: if the event cannot be attributed to a PID, refuse.
#   5. Log every decision (including refusals) to the AR log that the agent
#      actually ships to the manager.
#
# CHANGELOG (RH4 hardening)
#   The previous version contained an "Aggressive Response" block that killed
#   the PARENT process too. With an alert chain such as
#       explorer.exe -> cmd.exe -> vssadmin.exe
#   that walked all the way up and terminated the interactive desktop session.
#   Ancestor killing is now removed entirely.
#
# Log path note: the agent's ossec.conf collects
#   <agent>/active-response/active-responses.log
# so this script writes THERE. Writing to %ProgramData%\ossec-agent\... (as the
# old version did) produced logs the manager never saw.
# ==============================================================================

$ErrorActionPreference = 'Continue'

$LogFile = Join-Path $PSScriptRoot '..\active-responses.log'
$LogFile = [System.IO.Path]::GetFullPath($LogFile)

function Write-ARLog {
    param([string]$Message)
    $line = '{0} [kill-process] {1}' -f (Get-Date -Format 'yyyy-MM-ddTHH:mm:ss.fffK'), $Message
    try { Add-Content -LiteralPath $LogFile -Value $line -ErrorAction Stop } catch { }
    Write-Output $line
}

# --- Protected processes: killing any of these can brick or destabilise Windows
$ProtectedProcesses = @(
    'system', 'system idle process', 'registry', 'memory compression',
    'smss.exe', 'csrss.exe', 'wininit.exe', 'winlogon.exe',
    'lsass.exe', 'lsm.exe', 'services.exe', 'svchost.exe',
    'explorer.exe', 'dwm.exe', 'fontdrvhost.exe', 'spoolsv.exe',
    'wazuh-agent.exe', 'wazuhsvc', 'wazuh-modulesd.exe',
    'msmpeng.exe', 'nissrv.exe'
)

# --- Agents / LOLBins that are legitimate parents of malicious children.
#     Kept for LOGGING ONLY. Nothing is killed from this list.
$SuspiciousParents = @(
    'powershell.exe', 'pwsh.exe', 'cmd.exe', 'wscript.exe',
    'cscript.exe', 'mshta.exe', 'rundll32.exe', 'regsvr32.exe'
)

# ---------------------------------------------------------------- read input
$rawInput = [Console]::In.ReadLine()
if ([string]::IsNullOrWhiteSpace($rawInput)) { $rawInput = Read-Host }

if ([string]::IsNullOrWhiteSpace($rawInput)) {
    Write-ARLog 'ABORT: empty AR payload received.'
    exit 1
}

try {
    $arData = $rawInput | ConvertFrom-Json
    # Wazuh may hand over a JSON string that itself contains JSON
    if ($arData -is [string]) { $arData = $arData | ConvertFrom-Json }
} catch {
    Write-ARLog "ABORT: could not parse AR payload: $($_.Exception.Message)"
    exit 1
}

# Only the 'add' (contain) action terminates a process.
if ($arData.command -ne 'add') {
    Write-ARLog "SKIP: command '$($arData.command)' is not 'add'; nothing to kill."
    exit 0
}

$ruleId = $arData.parameters.alert.rule.id
$eventData = $arData.parameters.alert.data.win.eventdata

Write-ARLog "TRIGGER rule=$ruleId eventID=$($eventData.eventID)"

# ------------------------------------------------- attribute the target PID
# The offending process depends on which Sysmon event fired:
#   EID 1  (ProcessCreate)      -> the process being created
#   EID 5  (ProcessTerminate)   -> the process being terminated
#   EID 8  (CreateRemoteThread) -> the SOURCE process doing the injecting
#   EID 10 (ProcessAccess)      -> the SOURCE process touching lsass
# Never target the victim of 8/10 (e.g. lsass.exe) - that is the whole point
# of the event-aware selection.
$detectedEventId = [string]$eventData.eventID
if (-not $detectedEventId) {
    $ruleToEvent = @{
        '136020' = '1'; '136021' = '1'; '136022' = '1'
        '136030' = '1'; '136031' = '1'
        '136040' = '1'; '136042' = '1'
        '136041' = '10'
        '136050' = '1'; '136051' = '1'; '136052' = '1'
        '136055' = '1'; '136056' = '1'; '136057' = '1'
        '136060' = '11'; '136061' = '11'; '136062' = '11'
        '136090' = '8'
    }
    $detectedEventId = $ruleToEvent[[string]$ruleId]
}

$targetPidRaw = $null
$image       = $null
$parentPid   = $eventData.parentProcessId
$parentImage = $eventData.parentImage

switch ($detectedEventId) {
    '1' {
        $targetPidRaw = $eventData.processId
        $image        = $eventData.image
    }
    '5' {
        $targetPidRaw = $eventData.processId
        $image        = $eventData.image
    }
    '8' {
        $targetPidRaw = $eventData.sourceProcessId
        $image        = $eventData.sourceImage
    }
    '10' {
        $targetPidRaw = $eventData.sourceProcessId
        $image        = $eventData.sourceImage
    }
    default {
        # DYNAMIC FALLBACK: Extract PID dynamically from payload fields without relying on hardcoded rule IDs
        if ($eventData.sourceProcessId) {
            $targetPidRaw = $eventData.sourceProcessId
            $image        = $eventData.sourceImage
            Write-ARLog "DYNAMIC-DETECT: Extracted sourceProcessId=$targetPidRaw (image=$image)"
        } elseif ($eventData.processId) {
            $targetPidRaw = $eventData.processId
            $image        = $eventData.image
            Write-ARLog "DYNAMIC-DETECT: Extracted processId=$targetPidRaw (image=$image)"
        } elseif ($arData.parameters.alert.data.processId) {
            $targetPidRaw = $arData.parameters.alert.data.processId
            $image        = $arData.parameters.alert.data.image
            Write-ARLog "DYNAMIC-DETECT: Extracted alert processId=$targetPidRaw"
        } else {
            Write-ARLog "REFUSE: unknown Sysmon eventID '$detectedEventId' and no PID fields in payload - manual review required."
            exit 1
        }
    }
}

# --------------------------------------------------- hard safety interlocks
# Wazuh delivers Sysmon eventdata values as JSON STRINGS (e.g. "3864").
# Comparing that string against a number with -le coerces the NUMBER to a
# string, so "3864" -le 4 becomes "3864" -le "4" -> True, and the script
# wrongly refused to act on every real alert. Force a numeric cast first.
$targetPid = 0
if ($targetPidRaw) { [void][int]::TryParse([string]$targetPidRaw, [ref]$targetPid) }

if ($targetPid -le 4) {
    Write-ARLog "REFUSE: no usable target PID in alert (eventID=$detectedEventId, raw='$targetPidRaw')."
    exit 1
}

$leafName = if ($image) { (Split-Path -Leaf $image).ToLowerInvariant() } else { '' }

if ($ProtectedProcesses -contains $leafName) {
    Write-ARLog "GUARD: '$leafName' is a protected system process - kill SKIPPED (rule $ruleId)."
    if ($parentPid -and $parentImage) {
        Write-ARLog "GUARD-CONTEXT: parent was PID $parentPid ($parentImage) - logged only, not killed."
    }
    exit 0
}

# Never kill our own ancestry (would kill the agent mid-response).
try {
    $selfChain = @()
    $p = $PID
    while ($p -gt 0) {
        $selfChain += $p
        $proc = Get-CimInstance Win32_Process -Filter "ProcessId=$p" -ErrorAction Stop
        $p = $proc.ParentProcessId
    }
    if ($selfChain -contains [int]$targetPid) {
        Write-ARLog "GUARD: PID $targetPid is in the agent's own process ancestry - kill SKIPPED."
        exit 0
    }
} catch {
    Write-ARLog "WARN: could not verify self-ancestry for PID ${targetPid}: $($_.Exception.Message)"
}

if ($parentImage) {
    $parentLeaf = (Split-Path -Leaf $parentImage).ToLowerInvariant()
    if ($SuspiciousParents -contains $parentLeaf) {
        Write-ARLog "CONTEXT: parent PID $parentPid ($parentLeaf) is a known LOLBin - recorded for correlation, NOT killed."
    }
}

# ------------------------------------------------------------- do the kill
try {
    $proc = Get-Process -Id $targetPid -ErrorAction Stop
    $before = $proc.ProcessName

    if ($ProtectedProcesses -contains $before.ToLowerInvariant()) {
        Write-ARLog "GUARD: PID $targetPid resolved to protected process '$before' - kill SKIPPED."
        exit 0
    }

    Stop-Process -Id $targetPid -Force -ErrorAction Stop
    Write-ARLog "KILLED pid=$targetPid image=$image name=$before rule=$ruleId eventID=$detectedEventId"
} catch {
    Write-ARLog "FAILED pid=$targetPid image=$image rule=$ruleId error=$($_.Exception.Message)"
    exit 1
}

exit 0
