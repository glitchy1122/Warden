//! Event-driven VPN guard: WMI process killer, adapter takedown, firewall batch,
//! Chrome/Edge extension lockdown. Radmin is always allowed.
//!
//! Heavy work (netsh / Disable-NetAdapter / process sweep) runs in background
//! threads so Enable/Disable never blocks the UI.

#![cfg(windows)]

use parking_lot::Mutex;
use std::fs;
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};
use windows::core::PCWSTR;
use windows::Win32::Foundation::ERROR_SUCCESS;
use windows::Win32::System::Registry::{
    RegCloseKey, RegCreateKeyExW, RegDeleteTreeW, RegDeleteValueW, RegSetValueExW, HKEY_LOCAL_MACHINE,
    KEY_WRITE, REG_DWORD, REG_OPTION_NON_VOLATILE, REG_SZ, HKEY,
};

const VPN_PROCESS_NEEDLES: &[&str] = &[
    "nordvpn",
    "nordlynx",
    "openvpn",
    "ovpnhelper",
    "wireguard",
    "mullvad",
    "expressvpn",
    "surfshark",
    "protonvpn",
    "protonvpnserv",
    "windscribe",
    "cyberghost",
    "pia_",
    "privateinternetaccess",
    "tunnelbear",
    "hotspotshield",
    "astrill",
    "vyprvpn",
    "ipvanish",
    "purevpn",
    "softether",
    "vpnclient_x64",
    "vpnclient.exe",
    "outline.exe",
    "psiphon",
    "lantern.exe",
    "warpsvc",
    "warp-svc",
    "cloudflare-warp",
    "tailscaled",
    "tailscale-ipn",
    "zerotier",
    "hamachi",
    "globalprotect",
    "pangpa",
    "panmsa",
    "forticlient",
    "fortivpn",
    "vpnagent",
    "vpnui",
    "amnezia",
    "hiddify",
    "v2rayn",
    "clash-ver",
    "clash.exe",
    "nekoray",
    "sing-box",
    "shadowsocks",
    "ss-local",
    "qv2ray",
];

const RADMIN_ALLOW: &[&str] = &[
    "radmin",
    "rserver",
    "rvncviewer",
    "famatech",
    "radminviewer",
];

const WMI_WATCHER_PS1: &str = r#"
$ErrorActionPreference = 'Stop'
$watcher = New-Object System.Management.ManagementEventWatcher('SELECT ProcessID, ProcessName FROM Win32_ProcessStartTrace')
try {
  while ($true) {
    $e = $watcher.WaitForNextEvent()
    if ($null -eq $e) { continue }
    Write-Output ("{0}|{1}" -f $e.ProcessID, $e.ProcessName)
    [Console]::Out.Flush()
  }
} finally {
  $watcher.Stop()
  $watcher.Dispose()
}
"#;

pub struct VpnGuard {
    running: Arc<AtomicBool>,
    wmi_child: Mutex<Option<Child>>,
    wmi_handle: Mutex<Option<JoinHandle<()>>>,
    adapter_handle: Mutex<Option<JoinHandle<()>>>,
    side_handle: Mutex<Option<JoinHandle<()>>>,
}

impl VpnGuard {
    pub fn new() -> Self {
        Self {
            running: Arc::new(AtomicBool::new(false)),
            wmi_child: Mutex::new(None),
            wmi_handle: Mutex::new(None),
            adapter_handle: Mutex::new(None),
            side_handle: Mutex::new(None),
        }
    }

    /// Returns immediately. Firewall / adapters / process kill / registry run in background.
    pub fn start(&self) -> Result<(), String> {
        if self.running.swap(true, Ordering::SeqCst) {
            return Ok(());
        }

        let scripts = materialize_scripts()?;
        let watcher_path = scripts.join("wmi_process_watch.ps1");
        fs::write(&watcher_path, WMI_WATCHER_PS1).map_err(|e| e.to_string())?;

        // Side work must not block Enable Protection.
        let scripts_side = scripts.clone();
        let side = thread::Builder::new()
            .name("warden-vpn-side".into())
            .spawn(move || {
                let _ = run_bat_timeout(&scripts_side.join("firewall_rules.bat"), 8_000);
                let _ = lockdown_browser_extensions();
                kill_existing_vpn_processes();
                // Adapter takedown is optional and can stall on Windows — hard-timeout.
                let _ = run_bat_timeout(&scripts_side.join("disable_vpn_adapters.bat"), 5_000);
            })
            .map_err(|e| e.to_string())?;
        *self.side_handle.lock() = Some(side);

        let mut child = Command::new("powershell.exe")
            .args([
                "-NoProfile",
                "-NonInteractive",
                "-WindowStyle",
                "Hidden",
                "-ExecutionPolicy",
                "Bypass",
                "-File",
                &watcher_path.to_string_lossy(),
            ])
            .creation_flags(0x0800_0000)
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .stdin(Stdio::null())
            .spawn()
            .map_err(|e| format!("WMI watcher spawn failed: {e}"))?;

        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| "WMI watcher missing stdout".to_string())?;

        let running = self.running.clone();
        let scripts_wmi = scripts.clone();
        let reader = thread::Builder::new()
            .name("warden-vpn-wmi".into())
            .spawn(move || {
                let buf = BufReader::new(stdout);
                for line in buf.lines() {
                    if !running.load(Ordering::SeqCst) {
                        break;
                    }
                    let Ok(line) = line else { break };
                    let line = line.trim();
                    if line.is_empty() {
                        continue;
                    }
                    let Some((pid_s, name)) = line.split_once('|') else {
                        continue;
                    };
                    let Ok(pid) = pid_s.parse::<u32>() else {
                        continue;
                    };
                    if is_vpn_process(name) {
                        kill_pid(pid);
                        let _ = run_bat_timeout(
                            &scripts_wmi.join("disable_vpn_adapters.bat"),
                            5_000,
                        );
                    }
                }
            })
            .map_err(|e| e.to_string())?;

        *self.wmi_child.lock() = Some(child);
        *self.wmi_handle.lock() = Some(reader);

        let running2 = self.running.clone();
        let scripts_ad = scripts;
        let adapters = thread::Builder::new()
            .name("warden-vpn-adapters".into())
            .spawn(move || {
                // Rare catch-up only (~60s). Never on the enable path.
                while running2.load(Ordering::SeqCst) {
                    for _ in 0..600 {
                        if !running2.load(Ordering::SeqCst) {
                            return;
                        }
                        thread::sleep(Duration::from_millis(100));
                    }
                    let _ = run_bat_timeout(&scripts_ad.join("disable_vpn_adapters.bat"), 5_000);
                }
            })
            .map_err(|e| e.to_string())?;
        *self.adapter_handle.lock() = Some(adapters);
        Ok(())
    }

    /// Returns quickly. Does not wait on adapter scripts or PowerShell.
    pub fn stop(&self) {
        self.running.store(false, Ordering::SeqCst);

        if let Some(mut child) = self.wmi_child.lock().take() {
            let _ = child.kill();
            let _ = child.wait();
        }

        // Detach worker threads — joining them caused Enable/Disable hangs when a
        // bat/PowerShell call was mid-flight.
        let _ = self.wmi_handle.lock().take();
        let _ = self.adapter_handle.lock().take();
        let _ = self.side_handle.lock().take();

        thread::spawn(|| {
            if let Ok(scripts) = materialize_scripts() {
                let _ = run_bat_timeout(&scripts.join("firewall_rules_off.bat"), 5_000);
            }
            let _ = unlock_browser_extensions();
        });
    }
}

fn is_radmin(name: &str) -> bool {
    let n = name.to_ascii_lowercase();
    RADMIN_ALLOW.iter().any(|s| n.contains(s))
}

fn is_vpn_process(name: &str) -> bool {
    if is_radmin(name) {
        return false;
    }
    let n = name.to_ascii_lowercase();
    if n == "pia" || n.starts_with("pia.") {
        return true;
    }
    VPN_PROCESS_NEEDLES.iter().any(|s| n.contains(s))
}

fn kill_pid(pid: u32) {
    let _ = Command::new("taskkill")
        .args(["/F", "/PID", &pid.to_string()])
        .creation_flags(0x0800_0000)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
}

fn kill_existing_vpn_processes() {
    let mut child = match Command::new("powershell.exe")
        .args([
            "-NoProfile",
            "-NonInteractive",
            "-WindowStyle",
            "Hidden",
            "-ExecutionPolicy",
            "Bypass",
            "-Command",
            r#"
$ErrorActionPreference='SilentlyContinue'
$needles=@('nordvpn','nordlynx','openvpn','ovpnhelper','wireguard','mullvad','expressvpn','surfshark','protonvpn','windscribe','cyberghost','privateinternetaccess','tunnelbear','warpsvc','warp-svc','tailscaled','zerotier','softether','outline','psiphon','clash','v2rayn','amnezia','hiddify','globalprotect','forticlient','vpnagent','vpnui','cloudflare-warp','hamachi','nekoray')
$allow=@('radmin','rserver','famatech','rvncviewer')
Get-Process | ForEach-Object {
  $n=$_.ProcessName.ToLower()
  foreach ($a in $allow) { if ($n -like "*$a*") { return } }
  foreach ($s in $needles) {
    if ($n -like "*$s*" -or $n -eq 'pia') {
      Stop-Process -Id $_.Id -Force -ErrorAction SilentlyContinue
      break
    }
  }
}
"#,
        ])
        .creation_flags(0x0800_0000)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
    {
        Ok(c) => c,
        Err(_) => return,
    };
    wait_child_timeout(&mut child, 5_000);
}

fn materialize_scripts() -> Result<PathBuf, String> {
    let dir = std::env::temp_dir().join("warden-scripts");
    fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    let files = [
        (
            "firewall_rules.bat",
            include_str!("../scripts/firewall_rules.bat"),
        ),
        (
            "firewall_rules_off.bat",
            include_str!("../scripts/firewall_rules_off.bat"),
        ),
        (
            "disable_vpn_adapters.bat",
            include_str!("../scripts/disable_vpn_adapters.bat"),
        ),
        (
            "disable_vpn_adapters.ps1",
            include_str!("../scripts/disable_vpn_adapters.ps1"),
        ),
    ];
    for (name, body) in files {
        fs::write(dir.join(name), body).map_err(|e| e.to_string())?;
    }
    Ok(dir)
}

fn run_bat_timeout(path: &Path, timeout_ms: u64) -> Result<(), String> {
    if !path.is_file() {
        return Err(format!("missing script: {}", path.display()));
    }
    let mut child = Command::new("cmd.exe")
        .args(["/C", &path.to_string_lossy()])
        .creation_flags(0x0800_0000)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| e.to_string())?;
    wait_child_timeout(&mut child, timeout_ms);
    Ok(())
}

fn wait_child_timeout(child: &mut Child, timeout_ms: u64) {
    let start = Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(_)) => return,
            Ok(None) => {
                if start.elapsed() >= Duration::from_millis(timeout_ms) {
                    let _ = child.kill();
                    let _ = child.wait();
                    return;
                }
                thread::sleep(Duration::from_millis(50));
            }
            Err(_) => {
                let _ = child.kill();
                return;
            }
        }
    }
}

fn lockdown_browser_extensions() -> Result<(), String> {
    set_extension_blocklist(
        r"SOFTWARE\Policies\Google\Chrome\ExtensionInstallBlocklist",
        "*",
    )?;
    set_extension_blocklist(
        r"SOFTWARE\Policies\Microsoft\Edge\ExtensionInstallBlocklist",
        "*",
    )?;
    set_dword_value(r"SOFTWARE\Policies\Google\Chrome", "BlockExternalExtensions", 1)?;
    set_dword_value(r"SOFTWARE\Policies\Microsoft\Edge", "BlockExternalExtensions", 1)?;
    Ok(())
}

fn unlock_browser_extensions() -> Result<(), String> {
    delete_tree(r"SOFTWARE\Policies\Google\Chrome\ExtensionInstallBlocklist");
    delete_tree(r"SOFTWARE\Policies\Microsoft\Edge\ExtensionInstallBlocklist");
    delete_value(r"SOFTWARE\Policies\Google\Chrome", "BlockExternalExtensions");
    delete_value(r"SOFTWARE\Policies\Microsoft\Edge", "BlockExternalExtensions");
    Ok(())
}

fn set_extension_blocklist(path: &str, pattern: &str) -> Result<(), String> {
    set_sz_value(path, "1", pattern)
}

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

fn open_or_create_key(path: &str) -> Result<HKEY, String> {
    let path_w = wide(path);
    let mut key = HKEY::default();
    let status = unsafe {
        RegCreateKeyExW(
            HKEY_LOCAL_MACHINE,
            PCWSTR(path_w.as_ptr()),
            0,
            None,
            REG_OPTION_NON_VOLATILE,
            KEY_WRITE,
            None,
            &mut key,
            None,
        )
    };
    if status != ERROR_SUCCESS {
        return Err(format!("RegCreateKeyExW {path}: 0x{:08X}", status.0));
    }
    Ok(key)
}

fn set_sz_value(path: &str, name: &str, value: &str) -> Result<(), String> {
    let key = open_or_create_key(path)?;
    let name_w = wide(name);
    let value_w = wide(value);
    let bytes =
        unsafe { std::slice::from_raw_parts(value_w.as_ptr() as *const u8, value_w.len() * 2) };
    let status = unsafe { RegSetValueExW(key, PCWSTR(name_w.as_ptr()), 0, REG_SZ, Some(bytes)) };
    unsafe {
        let _ = RegCloseKey(key);
    }
    if status != ERROR_SUCCESS {
        return Err(format!("RegSetValueExW {path}\\{name}: 0x{:08X}", status.0));
    }
    Ok(())
}

fn set_dword_value(path: &str, name: &str, value: u32) -> Result<(), String> {
    let key = open_or_create_key(path)?;
    let name_w = wide(name);
    let bytes = value.to_le_bytes();
    let status =
        unsafe { RegSetValueExW(key, PCWSTR(name_w.as_ptr()), 0, REG_DWORD, Some(&bytes)) };
    unsafe {
        let _ = RegCloseKey(key);
    }
    if status != ERROR_SUCCESS {
        return Err(format!(
            "RegSetValueExW dword {path}\\{name}: 0x{:08X}",
            status.0
        ));
    }
    Ok(())
}

fn delete_tree(path: &str) {
    let path_w = wide(path);
    unsafe {
        let _ = RegDeleteTreeW(HKEY_LOCAL_MACHINE, PCWSTR(path_w.as_ptr()));
    }
}

fn delete_value(path: &str, name: &str) {
    let Ok(key) = open_or_create_key(path) else {
        return;
    };
    let name_w = wide(name);
    unsafe {
        let _ = RegDeleteValueW(key, PCWSTR(name_w.as_ptr()));
        let _ = RegCloseKey(key);
    }
}

trait CommandExtHidden {
    fn creation_flags(&mut self, flags: u32) -> &mut Self;
}

impl CommandExtHidden for Command {
    fn creation_flags(&mut self, flags: u32) -> &mut Self {
        use std::os::windows::process::CommandExt;
        CommandExt::creation_flags(self, flags)
    }
}
