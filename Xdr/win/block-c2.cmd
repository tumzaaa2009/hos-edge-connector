:: block-c2.cmd — Wazuh Active Response wrapper for block-c2.ps1
@echo off
setlocal
PowerShell.exe -ExecutionPolicy Bypass -NoProfile -File "%~dp0block-c2.ps1"
endlocal
exit /b %ERRORLEVEL%
