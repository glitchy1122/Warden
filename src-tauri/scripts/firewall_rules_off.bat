@echo off
netsh advfirewall firewall delete rule name="Warden Block OpenVPN UDP" >nul 2>&1
netsh advfirewall firewall delete rule name="Warden Block OpenVPN TCP" >nul 2>&1
netsh advfirewall firewall delete rule name="Warden Block WireGuard" >nul 2>&1
netsh advfirewall firewall delete rule name="Warden Block IPsec IKE" >nul 2>&1
netsh advfirewall firewall delete rule name="Warden Block IPsec NAT-T" >nul 2>&1
netsh advfirewall firewall delete rule name="Warden Block L2TP" >nul 2>&1
netsh advfirewall firewall delete rule name="Warden Block SoftEther" >nul 2>&1
exit /b 0
