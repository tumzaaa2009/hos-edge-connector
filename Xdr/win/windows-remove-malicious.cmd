@echo off
setlocal
PowerShell.exe -ExecutionPolicy Bypass -NoProfile -File "%~dp0windows-remove-malicious.ps1"
endlocal
exit /b %ERRORLEVEL%
