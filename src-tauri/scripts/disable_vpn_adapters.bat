@echo off
:: Warden — disable virtual VPN adapters (TAP / TUN / WireGuard / Wintun).
:: Radmin / Famatech adapters are never touched.

powershell.exe -NoProfile -NonInteractive -WindowStyle Hidden -ExecutionPolicy Bypass -File "%~dp0disable_vpn_adapters.ps1"
exit /b %ERRORLEVEL%
