@echo off
setlocal
set SCRIPT="%~dp0windows-remove-malicious.ps1"
if exist "%~dp0..\..\shared\windows-remove-malicious.ps1" (
    set SCRIPT="%~dp0..\..\shared\windows-remove-malicious.ps1"
)
if exist "%~dp0..\shared\windows-remove-malicious.ps1" (
    set SCRIPT="%~dp0..\shared\windows-remove-malicious.ps1"
)
if exist "%ProgramFiles(x86)%\ossec-agent\shared\windows-remove-malicious.ps1" (
    set SCRIPT="%ProgramFiles(x86)%\ossec-agent\shared\windows-remove-malicious.ps1"
)
if exist "%ProgramFiles%\ossec-agent\shared\windows-remove-malicious.ps1" (
    set SCRIPT="%ProgramFiles%\ossec-agent\shared\windows-remove-malicious.ps1"
)
PowerShell.exe -ExecutionPolicy Bypass -NoProfile -File %SCRIPT%
endlocal
exit /b %ERRORLEVEL%
