# active-response/bin/kill-process.ps1
# Reads Wazuh AR JSON from stdin, kills the offending PID, logs result.
$input_json = [Console]::In.ReadLine()
$data = $input_json | ConvertFrom-Json

$logfile = "$env:ProgramFiles(x86)\ossec-agent\active-response\active-responses.log"
if (-not (Test-Path -Path (Split-Path -Path $logfile -Parent))) {
    $logfile = "$env:ProgramFiles\ossec-agent\active-response\active-responses.log"
}
if (-not (Test-Path -Path (Split-Path -Path $logfile -Parent))) {
    $logfile = "$env:ProgramData\ossec-agent\active-response\active-responses.log"
}

function Write-Log($msg) { Add-Content -Path $logfile -Value "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') kill-process.ps1: $msg" }

if ($data.command -eq "add") {
    $alertData = $data.parameters.alert.data
    $eventId   = $data.parameters.alert.rule.id
    # Event-aware PID selection (blast-radius guard):
    #   Sysmon EID8/EID10 -> sourceProcessId = the ATTACKER process (never the target e.g. lsass)
    #   Sysmon EID1/EID5  -> processId       = the newly created/exiting process itself
    $ruleToEvent = @{ '120100'='10'; '120101'='8'; '100150'='8'; '100151'='8'; '136030'='1' }
    if (-not $alertData.win.system.eventID) {
        # fallback: derive from rule id mapping when raw event fields absent
        $mapped = $ruleToEvent[$eventId]
        if ($mapped) { $detectedEventId = $mapped } else { $detectedEventId = $null }
    } else {
        $detectedEventId = $alertData.win.system.eventID
    }

    switch ($detectedEventId) {
        '8'     { $targetPid = $alertData.win.eventdata.sourceProcessId; $image = $alertData.win.eventdata.sourceImage }
        '10'    { $targetPid = $alertData.win.eventdata.sourceProcessId; $image = $alertData.win.eventdata.sourceImage }
        '1'     { 
                  $targetPid = $alertData.win.eventdata.processId; $image = $alertData.win.eventdata.image 
                  $parentPid = $alertData.win.eventdata.parentProcessId; $parentImage = $alertData.win.eventdata.parentImage
                }
        '5'     { $targetPid = $alertData.win.eventdata.processId;       $image = $alertData.win.eventdata.image }
        default {
            Write-Log "Unknown eventId '$detectedEventId' - REFUSE TO KILL, manual review required"
            exit 1
        }
    }
    if (-not $targetPid) {
        Write-Log "No processID present in alert data — aborting (no unsafe fallback)."
        exit 1
    }

    # Verified Kill: Validate process name before killing to prevent PID reuse
    if ($image) {
        $expectedProcessName = [System.IO.Path]::GetFileNameWithoutExtension($image).ToLower()
        try {
            $runningProc = Get-Process -Id $targetPid -ErrorAction Stop
            $currentName = $runningProc.ProcessName.ToLower()
            if ($currentName -ne $expectedProcessName -and $expectedProcessName -notmatch $currentName) {
                Write-Log "Safeguard: PID $targetPid ($currentName) does not match expected image ($expectedProcessName) - suspected PID reuse. Kill aborted."
                exit 0
            }
        } catch {
            Write-Log "Process PID $targetPid already exited or not found."
            exit 0
        }
    }

    # Pre-kill Triage & Socket Evidence Capture
    try {
        $conns = Get-NetTCPConnection -OwningProcess $targetPid -ErrorAction SilentlyContinue |
            Select-Object -ExpandProperty RemoteAddress
        if ($conns) {
            Write-Log "Triage Evidence: PID $targetPid connections: $($conns -join ', ')"
        }
    } catch {}

    try {
        Stop-Process -Id $targetPid -Force -ErrorAction Stop
        Write-Log "Killed PID $targetPid ($image) in response to alert."
    } catch {
        Write-Log "Failed to kill PID $targetPid : $_"
    }
    
    if ($parentPid -and $parentImage) {
        $safeGuards = @("explorer.exe", "services.exe", "svchost.exe", "smss.exe", "csrss.exe", "wininit.exe", "lsass.exe", "lsm.exe", "winlogon.exe", "spoolsv.exe")
        $parentName = (Split-Path -Leaf $parentImage).ToLower()
        if ($safeGuards -contains $parentName) {
            Write-Log "Safeguard: Skipped killing parent PID $parentPid ($parentImage) because it is a system critical process."
        } else {
            try {
                Stop-Process -Id $parentPid -Force -ErrorAction Stop
                Write-Log "Killed parent PID $parentPid ($parentImage) in response to alert (Aggressive Response)."
            } catch {
                Write-Log "Failed to kill parent PID $parentPid : $_"
            }
        }
    }
}
