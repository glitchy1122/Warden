//! Non-Windows stub for VPN guard.

#![cfg(not(windows))]

pub struct VpnGuard;

impl VpnGuard {
    pub fn new() -> Self {
        Self
    }

    pub fn start(&self) -> Result<(), String> {
        Err("VPN guard is Windows-only".into())
    }

    pub fn stop(&self) {}
}
