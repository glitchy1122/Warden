//! Non-Windows stub.

#![cfg(not(windows))]

pub fn is_ipv4(value: &str) -> bool {
    value.parse::<std::net::Ipv4Addr>().is_ok()
}

pub fn block_ipv4(_ip: &str) -> Result<(), String> {
    Ok(())
}

pub fn unblock_ipv4(_ip: &str) -> Result<(), String> {
    Ok(())
}

pub fn clear_all_ip_blocks() {}

pub fn sync_ip_blocks(_entries: &[String]) {}
