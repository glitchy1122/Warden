@echo off
set PATH=%USERPROFILE%\.cargo\bin;%PATH%
cd /d "%~dp0"
npm.cmd run tauri dev
