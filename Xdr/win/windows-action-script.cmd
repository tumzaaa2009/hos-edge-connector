:: action-script.cmd — tiny wrapper; lets PowerShell read AR JSON from STDIN
@echo off
setlocal
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0windows-block-malicious.ps1"
endlocal
exit /b %ERRORLEVEL%
