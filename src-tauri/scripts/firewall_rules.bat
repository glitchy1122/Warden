@echo off
:: Warden — block common VPN ports (UDP-focused). Idempotent.
:: OpenVPN / WireGuard / IPsec / L2TP / SoftEther. Does not blanket-block HTTPS.

netsh advfirewall firewall delete rule name="Warden Block OpenVPN UDP" >nul 2>&1
netsh advfirewall firewall delete rule name="Warden Block OpenVPN TCP" >nul 2>&1
netsh advfirewall firewall delete rule name="Warden Block WireGuard" >nul 2>&1
netsh advfirewall firewall delete rule name="Warden Block IPsec IKE" >nul 2>&1
netsh advfirewall firewall delete rule name="Warden Block IPsec NAT-T" >nul 2>&1
netsh advfirewall firewall delete rule name="Warden Block L2TP" >nul 2>&1
netsh advfirewall firewall delete rule name="Warden Block SoftEther" >nul 2>&1

netsh advfirewall firewall add rule name="Warden Block OpenVPN UDP" dir=out action=block protocol=UDP remoteport=1194 enable=yes profile=any
netsh advfirewall firewall add rule name="Warden Block OpenVPN TCP" dir=out action=block protocol=TCP remoteport=1194 enable=yes profile=any
netsh advfirewall firewall add rule name="Warden Block WireGuard" dir=out action=block protocol=UDP remoteport=51820 enable=yes profile=any
netsh advfirewall firewall add rule name="Warden Block IPsec IKE" dir=out action=block protocol=UDP remoteport=500 enable=yes profile=any
netsh advfirewall firewall add rule name="Warden Block IPsec NAT-T" dir=out action=block protocol=UDP remoteport=4500 enable=yes profile=any
netsh advfirewall firewall add rule name="Warden Block L2TP" dir=out action=block protocol=UDP remoteport=1701 enable=yes profile=any
netsh advfirewall firewall add rule name="Warden Block SoftEther" dir=out action=block protocol=TCP remoteport=5555 enable=yes profile=any

exit /b 0
