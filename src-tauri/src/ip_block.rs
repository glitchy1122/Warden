//! Block custom IPv4 literals via Windows Firewall.
//! DNS filtering cannot catch `https://1.2.3.4/...` — browsers never query DNS for raw IPs.

#![cfg(windows)]

use std::os::windows::process::CommandExt;
use std::process::Command;

const CREATE_NO_WINDOW: u32 = 0x0800_0000;
const RULE_PREFIX: &str = "Warden Block IP ";

pub fn is_ipv4(value: &str) -> bool {
    value.parse::<std::net::Ipv4Addr>().is_ok()
}

pub fn rule_name(ip: &str) -> String {
    format!("{RULE_PREFIX}{ip}")
}

pub fn block_ipv4(ip: &str) -> Result<(), String> {
    if !is_ipv4(ip) {
        return Err(format!("not an IPv4 address: {ip}"));
    }
    // Idempotent: delete then add.
    let _ = unblock_ipv4(ip);
    let status = Command::new("netsh")
        .args([
            "advfirewall",
            "firewall",
            "add",
            "rule",
            &format!("name={}", rule_name(ip)),
            "dir=out",
            "action=block",
            "enable=yes",
            "profile=any",
            &format!("remoteip={ip}"),
        ])
        .creation_flags(CREATE_NO_WINDOW)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map_err(|e| e.to_string())?;
    if !status.success() {
        return Err(format!("firewall block failed for {ip}"));
    }
    // Also block inbound to that IP from this host (optional symmetry).
    let _ = Command::new("netsh")
        .args([
            "advfirewall",
            "firewall",
            "add",
            "rule",
            &format!("name={} in", rule_name(ip)),
            "dir=in",
            "action=block",
            "enable=yes",
            "profile=any",
            &format!("remoteip={ip}"),
        ])
        .creation_flags(CREATE_NO_WINDOW)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status();
    Ok(())
}

pub fn unblock_ipv4(ip: &str) -> Result<(), String> {
    let _ = Command::new("netsh")
        .args([
            "advfirewall",
            "firewall",
            "delete",
            "rule",
            &format!("name={}", rule_name(ip)),
        ])
        .creation_flags(CREATE_NO_WINDOW)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status();
    let _ = Command::new("netsh")
        .args([
            "advfirewall",
            "firewall",
            "delete",
            "rule",
            &format!("name={} in", rule_name(ip)),
        ])
        .creation_flags(CREATE_NO_WINDOW)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status();
    Ok(())
}

/// Remove every Warden IP block rule (used on disable).
pub fn clear_all_ip_blocks() {
    // netsh cannot delete by prefix easily — enumerate via show + delete known list from caller.
    // Fallback: PowerShell remove by display name prefix.
    let _ = Command::new("powershell.exe")
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
Get-NetFirewallRule -ErrorAction SilentlyContinue |
  Where-Object { $_.DisplayName -like 'Warden Block IP *' } |
  Remove-NetFirewallRule -Confirm:$false
"#,
        ])
        .creation_flags(CREATE_NO_WINDOW)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status();
}

pub fn sync_ip_blocks(entries: &[String]) {
    clear_all_ip_blocks();
    for entry in entries {
        if is_ipv4(entry) {
            let _ = block_ipv4(entry);
        }
    }
}
