@echo off
:: Build production UI + embed into release exe (custom-protocol, NOT localhost).
set PATH=%USERPROFILE%\.cargo\bin;%PATH%
cd /d "%~dp0"
call npm.cmd run build
if errorlevel 1 exit /b 1
cargo build --release --manifest-path src-tauri\Cargo.toml
if errorlevel 1 exit /b 1
echo.
echo OK: src-tauri\target\release\warden.exe
echo Launch with run-admin.cmd
