$ErrorActionPreference = 'SilentlyContinue'
# Only virtual tunnel adapters — never touch Wi-Fi / Ethernet / Radmin.
$skip = 'Loopback|Radmin|Famatech|Wi-Fi|WiFi|Ethernet|Local Area Connection'
$hit = 'TAP-Windows|TAP-Win32|Wintun|WireGuard|NordLynx|OpenVPN TAP|VPN Client|Cloudflare WARP|Mullvad|ExpressVPN|ProtonVPN|Surfshark|softether|hamachi|ZeroTier|zerotier|tailscale|GlobalProtect|forticlient|pangp|Windscribe'
Get-NetAdapter | Where-Object {
  $_.Status -ne 'Disabled' -and
  $_.InterfaceAlias -notmatch $skip -and
  (
    $_.InterfaceAlias -match $hit -or
    $_.DriverDescription -match $hit -or
    $_.InterfaceDescription -match $hit
  )
} | ForEach-Object {
  # -PassThru avoids some host hangs; still best-effort.
  Disable-NetAdapter -Name $_.Name -Confirm:$false -ErrorAction SilentlyContinue
}
