@echo off
:: Launch Warden elevated (required for WFP + binding DNS port 53)
set PATH=%USERPROFILE%\.cargo\bin;%PATH%
cd /d "%~dp0"
powershell -NoProfile -ExecutionPolicy Bypass -Command ^
  "Start-Process -FilePath 'npm.cmd' -ArgumentList 'run','tauri','dev' -Verb RunAs -WorkingDirectory '%cd%'"
