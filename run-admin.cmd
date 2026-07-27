@echo off
:: Launch release Warden elevated (WFP + DNS port 53 + VPN guard). No Vite/dev server needed.
cd /d "%~dp0"
set "EXE=%~dp0src-tauri\target\release\warden.exe"
if not exist "%EXE%" (
  echo Missing release build: %EXE%
  echo Build first: npm run build ^&^& cargo build --release --manifest-path src-tauri\Cargo.toml
  pause
  exit /b 1
)
powershell -NoProfile -ExecutionPolicy Bypass -Command ^
  "Start-Process -FilePath '%EXE%' -Verb RunAs"
