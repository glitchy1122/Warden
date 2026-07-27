//! Local DNS enforcement (WFP).
//! - Block all outbound :53 except loopback + Warden.exe (ALE_APP_ID)
//! - Pin active adapters to 127.0.0.1 / ::1 once at enable
//! VPN process/adapter/firewall handling lives in `vpn_guard` (event-driven).

#![cfg(windows)]

use std::ffi::c_void;
use std::mem::zeroed;
use std::os::windows::ffi::OsStrExt;
use std::ptr;
use windows::core::{GUID, PCWSTR, PWSTR};
use windows::Win32::Foundation::{ERROR_SUCCESS, HANDLE};
use windows::Win32::NetworkManagement::WindowsFilteringPlatform::*;
use windows::Win32::System::Rpc::RPC_C_AUTHN_WINNT;

const SUBLAYER_NAME: &str = "Warden DNS Guard";

// DoH hostnames that Warden NXDOMAINs.
// Do NOT include dns.google / cloudflare-dns.com — that bricks Brave/Edge Secure DNS.
pub const DOH_HOSTS: &[&str] = &[
    "dns.adguard.com",
    "dns-unfiltered.adguard.com",
    "doh.opendns.com",
    "doh.dns.sb",
    "dns.quad9.net",
    "dns9.quad9.net",
];

struct EngineHandle(HANDLE);
unsafe impl Send for EngineHandle {}
unsafe impl Sync for EngineHandle {}

struct AppIdOwned {
    bytes: Vec<u8>,
}
unsafe impl Send for AppIdOwned {}
unsafe impl Sync for AppIdOwned {}

impl AppIdOwned {
    fn blob(&mut self) -> FWP_BYTE_BLOB {
        FWP_BYTE_BLOB {
            size: self.bytes.len() as u32,
            data: self.bytes.as_mut_ptr(),
        }
    }
}

pub struct WfpGuard {
    engine: Option<EngineHandle>,
    sublayer_key: GUID,
    filter_keys: Vec<GUID>,
    _app_id: Option<AppIdOwned>,
}

impl WfpGuard {
    pub fn new() -> Self {
        Self {
            engine: None,
            sublayer_key: GUID::zeroed(),
            filter_keys: Vec::new(),
            _app_id: None,
        }
    }

    pub fn is_active(&self) -> bool {
        self.engine.is_some()
    }

    pub fn start(&mut self) -> Result<(), String> {
        if self.engine.is_some() {
            return Ok(());
        }
        match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| unsafe {
            self.start_inner()
        })) {
            Ok(r) => r,
            Err(_) => Err("WFP setup panicked. Run as Administrator.".into()),
        }
    }

    unsafe fn start_inner(&mut self) -> Result<(), String> {
        let mut session: FWPM_SESSION0 = zeroed();
        session.flags = FWPM_SESSION_FLAG_DYNAMIC;

        let mut engine = HANDLE::default();
        let status = FwpmEngineOpen0(
            PCWSTR::null(),
            RPC_C_AUTHN_WINNT,
            None,
            Some(&session),
            &mut engine,
        );
        if status != ERROR_SUCCESS.0 {
            return Err(format!(
                "FwpmEngineOpen0 failed (0x{status:08X}). Run as Administrator."
            ));
        }

        let sublayer_key = GUID::new().map_err(|e| e.to_string())?;
        if let Err(e) = add_sublayer(engine, sublayer_key) {
            let _ = FwpmEngineClose0(engine);
            return Err(e);
        }

        let mut app_id = load_self_app_id()?;
        let mut blob = app_id.blob();
        let mut keys = Vec::new();

        // 1) Anyone → loopback DNS (proxy)
        for layer in [
            FWPM_LAYER_ALE_AUTH_CONNECT_V4,
            FWPM_LAYER_OUTBOUND_TRANSPORT_V4,
        ] {
            keys.push(add_loopback_v4_permit(engine, sublayer_key, layer)?);
        }
        for layer in [
            FWPM_LAYER_ALE_AUTH_CONNECT_V6,
            FWPM_LAYER_OUTBOUND_TRANSPORT_V6,
        ] {
            keys.push(add_loopback_v6_permit(engine, sublayer_key, layer)?);
        }

        // 2) Only Warden.exe → any remote :53 (upstream forward)
        for layer in [FWPM_LAYER_ALE_AUTH_CONNECT_V4, FWPM_LAYER_ALE_AUTH_CONNECT_V6] {
            keys.push(add_self_dns_permit(engine, sublayer_key, layer, &mut blob)?);
        }

        // 3) Block everyone else on :53
        for layer in [
            FWPM_LAYER_ALE_AUTH_CONNECT_V4,
            FWPM_LAYER_ALE_AUTH_CONNECT_V6,
            FWPM_LAYER_OUTBOUND_TRANSPORT_V4,
            FWPM_LAYER_OUTBOUND_TRANSPORT_V6,
        ] {
            keys.push(add_dns_block(engine, sublayer_key, layer)?);
        }

        self.engine = Some(EngineHandle(engine));
        self.sublayer_key = sublayer_key;
        self.filter_keys = keys;
        self._app_id = Some(app_id);
        Ok(())
    }

    pub fn stop(&mut self) {
        if let Some(EngineHandle(engine)) = self.engine.take() {
            unsafe {
                for key in self.filter_keys.drain(..) {
                    let _ = FwpmFilterDeleteByKey0(engine, &key);
                }
                let _ = FwpmSubLayerDeleteByKey0(engine, &self.sublayer_key);
                let _ = FwpmEngineClose0(engine);
            }
        }
        self._app_id = None;
    }
}

impl Drop for WfpGuard {
    fn drop(&mut self) {
        self.stop();
    }
}

unsafe fn load_self_app_id() -> Result<AppIdOwned, String> {
    let exe = std::env::current_exe().map_err(|e| e.to_string())?;
    let wide: Vec<u16> = exe
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    let mut app_id: *mut FWP_BYTE_BLOB = ptr::null_mut();
    let status = FwpmGetAppIdFromFileName0(PCWSTR(wide.as_ptr()), &mut app_id);
    if status != ERROR_SUCCESS.0 || app_id.is_null() {
        return Err(format!("FwpmGetAppIdFromFileName0 failed (0x{status:08X})"));
    }
    let src = &*app_id;
    let mut bytes = vec![0u8; src.size as usize];
    if !bytes.is_empty() && !src.data.is_null() {
        ptr::copy_nonoverlapping(src.data, bytes.as_mut_ptr(), bytes.len());
    }
    let mut free_ptr = app_id as *mut c_void;
    FwpmFreeMemory0(&mut free_ptr);
    Ok(AppIdOwned { bytes })
}

unsafe fn add_sublayer(engine: HANDLE, key: GUID) -> Result<(), String> {
    let name: Vec<u16> = SUBLAYER_NAME.encode_utf16().chain(std::iter::once(0)).collect();
    let mut sub: FWPM_SUBLAYER0 = zeroed();
    sub.subLayerKey = key;
    sub.displayData.name = PWSTR(name.as_ptr() as *mut _);
    sub.weight = 0x8000;
    let status = FwpmSubLayerAdd0(engine, &sub, None);
    if status != ERROR_SUCCESS.0 {
        let _ = FwpmSubLayerDeleteByKey0(engine, &key);
        let s2 = FwpmSubLayerAdd0(engine, &sub, None);
        if s2 != ERROR_SUCCESS.0 {
            return Err(format!("FwpmSubLayerAdd0 failed (0x{s2:08X})"));
        }
    }
    Ok(())
}

unsafe fn add_dns_block(engine: HANDLE, sublayer: GUID, layer: GUID) -> Result<GUID, String> {
    let key = GUID::new().map_err(|e| e.to_string())?;
    let name: Vec<u16> = "Warden block DNS"
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();
    let mut cond: FWPM_FILTER_CONDITION0 = zeroed();
    cond.fieldKey = FWPM_CONDITION_IP_REMOTE_PORT;
    cond.matchType = FWP_MATCH_EQUAL;
    cond.conditionValue.r#type = FWP_UINT16;
    cond.conditionValue.Anonymous.uint16 = 53;

    let mut f: FWPM_FILTER0 = zeroed();
    f.filterKey = key;
    f.displayData.name = PWSTR(name.as_ptr() as *mut _);
    f.layerKey = layer;
    f.subLayerKey = sublayer;
    f.weight.r#type = FWP_UINT8;
    f.weight.Anonymous.uint8 = 1;
    f.numFilterConditions = 1;
    f.filterCondition = &mut cond;
    f.action.r#type = FWP_ACTION_BLOCK;
    let status = FwpmFilterAdd0(engine, &f, None, None);
    if status != ERROR_SUCCESS.0 {
        return Err(format!("block filter failed (0x{status:08X})"));
    }
    Ok(key)
}

unsafe fn add_loopback_v4_permit(
    engine: HANDLE,
    sublayer: GUID,
    layer: GUID,
) -> Result<GUID, String> {
    let key = GUID::new().map_err(|e| e.to_string())?;
    let name: Vec<u16> = "Warden loopback v4"
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();
    let mut conds: [FWPM_FILTER_CONDITION0; 2] = zeroed();
    conds[0].fieldKey = FWPM_CONDITION_IP_REMOTE_PORT;
    conds[0].matchType = FWP_MATCH_EQUAL;
    conds[0].conditionValue.r#type = FWP_UINT16;
    conds[0].conditionValue.Anonymous.uint16 = 53;
    let mut addr = FWP_V4_ADDR_AND_MASK {
        addr: u32::from_be_bytes([127, 0, 0, 1]),
        mask: u32::from_be_bytes([255, 255, 255, 255]),
    };
    conds[1].fieldKey = FWPM_CONDITION_IP_REMOTE_ADDRESS;
    conds[1].matchType = FWP_MATCH_EQUAL;
    conds[1].conditionValue.r#type = FWP_V4_ADDR_MASK;
    conds[1].conditionValue.Anonymous.v4AddrMask = &mut addr;

    let mut f: FWPM_FILTER0 = zeroed();
    f.filterKey = key;
    f.displayData.name = PWSTR(name.as_ptr() as *mut _);
    f.layerKey = layer;
    f.subLayerKey = sublayer;
    f.weight.r#type = FWP_UINT8;
    f.weight.Anonymous.uint8 = 15;
    f.numFilterConditions = 2;
    f.filterCondition = conds.as_mut_ptr();
    f.action.r#type = FWP_ACTION_PERMIT;
    let status = FwpmFilterAdd0(engine, &f, None, None);
    if status != ERROR_SUCCESS.0 {
        return Err(format!("loopback v4 permit failed (0x{status:08X})"));
    }
    Ok(key)
}

unsafe fn add_loopback_v6_permit(
    engine: HANDLE,
    sublayer: GUID,
    layer: GUID,
) -> Result<GUID, String> {
    let key = GUID::new().map_err(|e| e.to_string())?;
    let name: Vec<u16> = "Warden loopback v6"
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();
    let mut conds: [FWPM_FILTER_CONDITION0; 2] = zeroed();
    conds[0].fieldKey = FWPM_CONDITION_IP_REMOTE_PORT;
    conds[0].matchType = FWP_MATCH_EQUAL;
    conds[0].conditionValue.r#type = FWP_UINT16;
    conds[0].conditionValue.Anonymous.uint16 = 53;

    // ::1 / 128
    let mut addr = FWP_V6_ADDR_AND_MASK {
        addr: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
        prefixLength: 128,
    };
    conds[1].fieldKey = FWPM_CONDITION_IP_REMOTE_ADDRESS;
    conds[1].matchType = FWP_MATCH_EQUAL;
    conds[1].conditionValue.r#type = FWP_V6_ADDR_MASK;
    conds[1].conditionValue.Anonymous.v6AddrMask = &mut addr;

    let mut f: FWPM_FILTER0 = zeroed();
    f.filterKey = key;
    f.displayData.name = PWSTR(name.as_ptr() as *mut _);
    f.layerKey = layer;
    f.subLayerKey = sublayer;
    f.weight.r#type = FWP_UINT8;
    f.weight.Anonymous.uint8 = 15;
    f.numFilterConditions = 2;
    f.filterCondition = conds.as_mut_ptr();
    f.action.r#type = FWP_ACTION_PERMIT;
    let status = FwpmFilterAdd0(engine, &f, None, None);
    if status != ERROR_SUCCESS.0 {
        return Err(format!("loopback v6 permit failed (0x{status:08X})"));
    }
    Ok(key)
}

unsafe fn add_self_dns_permit(
    engine: HANDLE,
    sublayer: GUID,
    layer: GUID,
    app_blob: &mut FWP_BYTE_BLOB,
) -> Result<GUID, String> {
    let key = GUID::new().map_err(|e| e.to_string())?;
    let name: Vec<u16> = "Warden self DNS"
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();
    let mut conds: [FWPM_FILTER_CONDITION0; 2] = zeroed();
    conds[0].fieldKey = FWPM_CONDITION_IP_REMOTE_PORT;
    conds[0].matchType = FWP_MATCH_EQUAL;
    conds[0].conditionValue.r#type = FWP_UINT16;
    conds[0].conditionValue.Anonymous.uint16 = 53;
    conds[1].fieldKey = FWPM_CONDITION_ALE_APP_ID;
    conds[1].matchType = FWP_MATCH_EQUAL;
    conds[1].conditionValue.r#type = FWP_BYTE_BLOB_TYPE;
    conds[1].conditionValue.Anonymous.byteBlob = app_blob;

    let mut f: FWPM_FILTER0 = zeroed();
    f.filterKey = key;
    f.displayData.name = PWSTR(name.as_ptr() as *mut _);
    f.layerKey = layer;
    f.subLayerKey = sublayer;
    f.weight.r#type = FWP_UINT8;
    f.weight.Anonymous.uint8 = 15;
    f.numFilterConditions = 2;
    f.filterCondition = conds.as_mut_ptr();
    f.action.r#type = FWP_ACTION_PERMIT;
    let status = FwpmFilterAdd0(engine, &f, None, None);
    if status != ERROR_SUCCESS.0 {
        return Err(format!(
            "Warden self DNS permit failed (0x{status:08X}). App ID filter rejected."
        ));
    }
    Ok(key)
}

/// Pin IPv4 DNS to the local proxy once. Do NOT force IPv6 DNS to ::1 —
/// if the IPv6 proxy isn't accepting queries, dual-stack browsers (Brave/Chrome)
/// show "no internet" / broken Google even when IPv4 DNS is fine.
///
/// Note: older Windows 10 builds reject `-AddressFamily` on Set-DnsClientServerAddress.
pub fn apply_local_dns() -> Result<String, String> {
    let script = r#"
$ErrorActionPreference = 'Stop'
Get-DnsClientNrptRule -ErrorAction SilentlyContinue | ForEach-Object {
  Remove-DnsClientNrptRule -Name $_.Name -Force -ErrorAction SilentlyContinue
}
$up = Get-NetAdapter -ErrorAction SilentlyContinue | Where-Object {
  $_.Status -eq 'Up' -and $_.InterfaceAlias -notmatch 'Loopback|Radmin|Famatech'
}
if (-not $up) { throw 'No active network adapter found' }
$backup = @()
foreach ($nic in $up) {
  $addrs = @()
  try {
    $v4 = Get-DnsClientServerAddress -InterfaceIndex $nic.ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue
    if ($v4) { $addrs = @($v4.ServerAddresses) }
  } catch {
    $all = Get-DnsClientServerAddress -InterfaceIndex $nic.ifIndex -ErrorAction SilentlyContinue
    if ($all) { $addrs = @($all.ServerAddresses) }
  }
  $backup += [pscustomobject]@{
    InterfaceIndex = $nic.ifIndex
    InterfaceAlias = $nic.InterfaceAlias
    ServerAddresses = ($addrs -join ',')
  }
  # Win10 19045: Set-DnsClientServerAddress has no -AddressFamily parameter.
  Set-DnsClientServerAddress -InterfaceIndex $nic.ifIndex -ServerAddresses @('127.0.0.1') -ErrorAction Stop | Out-Null
  # Leave IPv6 DNS on DHCP/automatic — do not point at ::1.
  try { netsh interface ipv6 set dnsservers name="$($nic.InterfaceAlias)" dhcp | Out-Null } catch {}
}
$backup | ConvertTo-Json -Compress
"#;
    run_powershell(script)
}

pub fn restore_dns(backup_json: &str) -> Result<(), String> {
    if backup_json.trim().is_empty() || backup_json.trim() == "null" {
        return Ok(());
    }
    let escaped = backup_json.replace('\'', "''");
    let script = format!(
        r#"
$ErrorActionPreference = 'Continue'
$backup = '{escaped}' | ConvertFrom-Json
if ($null -eq $backup) {{ return }}
foreach ($a in @($backup)) {{
  $servers = @()
  if ($a.ServerAddresses) {{
    $servers = $a.ServerAddresses -split ',' | Where-Object {{ $_ -and $_.Trim() -ne '' }}
  }}
  if ($servers.Count -gt 0) {{
    Set-DnsClientServerAddress -InterfaceIndex $a.InterfaceIndex -ServerAddresses $servers | Out-Null
  }} else {{
    Set-DnsClientServerAddress -InterfaceIndex $a.InterfaceIndex -ResetServerAddresses | Out-Null
  }}
  try {{ netsh interface ipv6 set dnsservers name="$($a.InterfaceAlias)" dhcp | Out-Null }} catch {{}}
}}
"#
    );
    let _ = run_powershell(&script)?;
    Ok(())
}

fn run_powershell(script: &str) -> Result<String, String> {
    use std::os::windows::process::CommandExt;
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;
    let output = std::process::Command::new("powershell.exe")
        .args([
            "-NoProfile",
            "-NonInteractive",
            "-WindowStyle",
            "Hidden",
            "-ExecutionPolicy",
            "Bypass",
            "-Command",
            script,
        ])
        .creation_flags(CREATE_NO_WINDOW)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .stdin(std::process::Stdio::null())
        .output()
        .map_err(|e| format!("powershell failed: {e}"))?;
    if !output.status.success() {
        return Err(format!(
            "DNS configuration failed: {}",
            String::from_utf8_lossy(&output.stderr)
        ));
    }
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}
