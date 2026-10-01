:: isolate-host.cmd — Wazuh Active Response wrapper for isolate-host.ps1
@echo off
setlocal
PowerShell.exe -ExecutionPolicy Bypass -NoProfile -File "%~dp0isolate-host.ps1"
endlocal
exit /b %ERRORLEVEL%
