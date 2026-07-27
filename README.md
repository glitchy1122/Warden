# Warden (Phase 2)

Local Windows blocklist + VPN/extension guard.

## DNS filtering model

Browsers talk to **Warden on `127.0.0.1:53`** (IPv4 NIC DNS is switched only while armed).  
Warden runs Bloom / custom checks, then forwards **allowed** queries to:

- primary: `1.1.1.1`
- fallback: `8.8.8.8`

IPv6 DNS is left on DHCP (not forced to `::1`). On disable, previous IPv4 DNS is restored.

## Also

- **VPN guard** — WMI kill list, adapter takedown, firewall VPN ports (Radmin allowed)
- **Browser lockdown** — Chrome/Edge extension install blocklist
- **Build-time Bloom** — porn/gambling lists baked at compile time (no runtime download)

## Requirements

- Windows 10/11, Admin for enable
- Rust (MSVC), Node.js

## Production

```powershell
.\build-release.cmd
.\run-admin.cmd
```

## License

Proprietary — **GLITCH**. See [LICENSE](LICENSE). Use only with GLITCH's permission.
