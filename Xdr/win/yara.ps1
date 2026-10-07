#==============================================================
# Wazuh Active Response - YARA (Windows)
# Install:
# C:\Program Files (x86)\ossec-agent\active-response\bin\yara.ps1
#==============================================================

$ErrorActionPreference = "SilentlyContinue"

$OSSEC_PATH = "${env:ProgramFiles(x86)}\ossec-agent"

$LOGFILE = "$OSSEC_PATH\active-response\active-responses.log"

$YARA = "$OSSEC_PATH\active-response\bin\yara\yara64.exe"

$RULES = "$OSSEC_PATH\shared\yara_rules.yar"

function Write-Log {
    param($Text)

    $time = Get-Date -Format "yyyy-MM-ddTHH:mm:ssK"
    "$time yara.ps1: $Text" | Out-File $LOGFILE -Append -Encoding utf8
}

Write-Log "[DEBUG] Script triggered."

#----------------------------------------------------------
# Read JSON from Wazuh
#----------------------------------------------------------

$InputJson = [Console]::In.ReadToEnd()

Write-Log "[DEBUG] Raw Input: $InputJson"

try {
    $Json = $InputJson | ConvertFrom-Json
}
catch {
    Write-Log "[ERROR] Invalid JSON."
    exit 0
}

#----------------------------------------------------------
# Get File Path
#----------------------------------------------------------

$FilePath = $Json.parameters.alert.syscheck.path

if ([string]::IsNullOrWhiteSpace($FilePath)) {

    if ($Json.parameters.extra_args.Count -gt 0) {
        $FilePath = $Json.parameters.extra_args[0]
    }
}

if ([string]::IsNullOrWhiteSpace($FilePath)) {

    Write-Log "[ERROR] No valid file path."

    exit 0
}

if (!(Test-Path $FilePath)) {

    Write-Log "[ERROR] File not found : $FilePath"

    exit 0
}

$FilePath = (Resolve-Path $FilePath).Path

Write-Log "[INFO] SCAN_START file=$FilePath"

#----------------------------------------------------------
# Check YARA
#----------------------------------------------------------

if (!(Test-Path $YARA)) {

    Write-Log "[ERROR] yara64.exe not found."

    exit 1
}

if (!(Test-Path $RULES)) {

    Write-Log "[ERROR] yara_rules.yar not found."

    exit 1
}

Start-Sleep -Seconds 2

Write-Log "[DEBUG] Executing YARA..."

#----------------------------------------------------------
# Execute YARA
#----------------------------------------------------------

$Result = & "$YARA" -r "$RULES" "$FilePath" 2>&1

$ExitCode = $LASTEXITCODE

Write-Log "[DEBUG] ExitCode=$ExitCode"

#----------------------------------------------------------
# Malware Found
#----------------------------------------------------------

if (($ExitCode -eq 0) -and ($Result.Count -gt 0)) {

    $Rule = ($Result | ForEach-Object {

        ($_ -split '\s+')[0]

    }) -join ','

    Write-Log "[WARN] MALWARE_DETECTED rule=$Rule"

    $SHA256 = (Get-FileHash $FilePath -Algorithm SHA256).Hash

    $MD5 = (Get-FileHash $FilePath -Algorithm MD5).Hash

    Write-Log "[DEBUG] SHA256=$SHA256"

    Write-Output (@{
        event="yara"
        action="detect"
        level="INFO"
        rule=$Rule
        file=$FilePath
        sha256=$SHA256
        md5=$MD5
    } | ConvertTo-Json -Compress)

    Remove-Item $FilePath -Force

    if (!(Test-Path $FilePath)) {

        Write-Log "[INFO] File deleted successfully."

    }
    else {

        Write-Log "[ERROR] Failed to delete file."

    }

}
elseif ($ExitCode -eq 1) {

    Write-Log "[INFO] CLEAN"

}
else {

    Write-Log "[ERROR] YARA scan failed."

    Write-Log "$Result"

}

Write-Log "[DEBUG] Script completed."

exit 0
