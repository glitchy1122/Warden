//! Event-driven local DNS proxy. Idle recv → ~0% CPU.
//! Fast path: finance bypass + single primary upstream (no multi-server stalls).

use crate::lookup::{BlockSource, LookupEngine};
#[cfg(windows)]
use crate::wfp::DOH_HOSTS;
use parking_lot::Mutex;
use serde::Serialize;
use std::net::{SocketAddr, UdpSocket};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const PRIMARY_UPSTREAM: &str = "1.1.1.1:53";
const FALLBACK_UPSTREAM: &str = "8.8.8.8:53";
const MAX_RECENT: usize = 40;

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BlockEvent {
    pub domain: String,
    pub source: BlockSource,
    pub at: u64,
}

pub struct DnsProxy {
    running: Arc<AtomicBool>,
    blocked_total: Arc<AtomicU64>,
    allowed_total: Arc<AtomicU64>,
    recent: Arc<Mutex<Vec<BlockEvent>>>,
    handle: Mutex<Option<JoinHandle<()>>>,
}

impl DnsProxy {
    pub fn new() -> Self {
        Self {
            running: Arc::new(AtomicBool::new(false)),
            blocked_total: Arc::new(AtomicU64::new(0)),
            allowed_total: Arc::new(AtomicU64::new(0)),
            recent: Arc::new(Mutex::new(Vec::new())),
            handle: Mutex::new(None),
        }
    }

    pub fn is_running(&self) -> bool {
        self.running.load(Ordering::SeqCst)
    }

    pub fn blocked_total(&self) -> u64 {
        self.blocked_total.load(Ordering::Relaxed)
    }

    pub fn allowed_total(&self) -> u64 {
        self.allowed_total.load(Ordering::Relaxed)
    }

    pub fn recent_blocks(&self) -> Vec<BlockEvent> {
        self.recent.lock().clone()
    }

    pub fn start(&self, engine: Arc<LookupEngine>) -> Result<(), String> {
        if self.is_running() {
            return Ok(());
        }

        let socket_v4 = UdpSocket::bind("127.0.0.1:53").map_err(|e| {
            format!("bind 127.0.0.1:53 failed (run as Administrator): {e}")
        })?;
        socket_v4
            .set_read_timeout(Some(Duration::from_millis(250)))
            .map_err(|e| e.to_string())?;

        // Shared upstream with TXID filtering (avoids reply mix-ups without
        // binding a new socket on every query — that path was flaky under WFP).
        let upstream = UdpSocket::bind("0.0.0.0:0").map_err(|e| e.to_string())?;
        upstream
            .set_read_timeout(Some(Duration::from_millis(1200)))
            .map_err(|e| e.to_string())?;
        let upstream = Arc::new(Mutex::new(upstream));

        self.running.store(true, Ordering::SeqCst);
        let running = self.running.clone();
        let blocked_total = self.blocked_total.clone();
        let allowed_total = self.allowed_total.clone();
        let recent = self.recent.clone();

        let handle = thread::Builder::new()
            .name("warden-dns".into())
            .spawn(move || {
                let mut buf = [0u8; 2048];
                let mut resp = [0u8; 4096];
                while running.load(Ordering::SeqCst) {
                    if let Ok((len, peer)) = socket_v4.recv_from(&mut buf) {
                        handle_query(
                            &socket_v4,
                            &upstream,
                            &mut resp,
                            peer,
                            &buf[..len],
                            &engine,
                            &blocked_total,
                            &allowed_total,
                            &recent,
                        );
                    }
                }
            })
            .map_err(|e| e.to_string())?;

        *self.handle.lock() = Some(handle);
        Ok(())
    }

    /// Probe 1.1.1.1 / 8.8.8.8 before we rewrite NIC DNS.
    pub fn smoke_test_upstream(&self) -> Result<(), String> {
        let mut resp = [0u8; 512];
        let packet = build_query_a("example.com");
        let sock = UdpSocket::bind("0.0.0.0:0").map_err(|e| e.to_string())?;
        sock.set_read_timeout(Some(Duration::from_millis(1500)))
            .map_err(|e| e.to_string())?;
        for server in [PRIMARY_UPSTREAM, FALLBACK_UPSTREAM] {
            if sock.send_to(&packet, server).is_err() {
                continue;
            }
            if let Ok((n, _)) = sock.recv_from(&mut resp) {
                if n >= 12 {
                    return Ok(());
                }
            }
        }
        Err("no response from 1.1.1.1 or 8.8.8.8".into())
    }

    pub fn stop(&self) {
        self.running.store(false, Ordering::SeqCst);
        let _ = self.handle.lock().take();
    }
}

fn handle_query(
    socket: &UdpSocket,
    upstream: &Mutex<UdpSocket>,
    resp: &mut [u8],
    peer: SocketAddr,
    packet: &[u8],
    engine: &LookupEngine,
    blocked_total: &AtomicU64,
    allowed_total: &AtomicU64,
    recent: &Mutex<Vec<BlockEvent>>,
) {
    let Some(domain) = extract_qname(packet) else {
        if let Some(response) = forward_upstream(upstream, resp, packet) {
            let _ = socket.send_to(&response, peer);
        }
        return;
    };

    if is_doh_host(&domain) {
        blocked_total.fetch_add(1, Ordering::Relaxed);
        if let Some(response) = build_nxdomain(packet) {
            let _ = socket.send_to(&response, peer);
        }
        return;
    }

    // Single path: custom → bypass → bloom (see LookupEngine::lookup).
    let result = engine.lookup(&domain);
    if result.blocked {
        blocked_total.fetch_add(1, Ordering::Relaxed);
        let event = BlockEvent {
            domain: result.domain.clone(),
            source: result.source,
            at: now_secs(),
        };
        {
            let mut guard = recent.lock();
            guard.insert(0, event);
            guard.truncate(MAX_RECENT);
        }
        if let Some(response) = build_nxdomain(packet) {
            let _ = socket.send_to(&response, peer);
        }
        return;
    }

    allowed_total.fetch_add(1, Ordering::Relaxed);
    if let Some(response) = forward_upstream(upstream, resp, packet) {
        let _ = socket.send_to(&response, peer);
    } else if let Some(response) = build_servfail(packet) {
        let _ = socket.send_to(&response, peer);
    }
}

fn is_doh_host(domain: &str) -> bool {
    #[cfg(windows)]
    {
        let d = domain.to_ascii_lowercase();
        DOH_HOSTS
            .iter()
            .any(|h| d == *h || d.ends_with(&format!(".{h}")))
    }
    #[cfg(not(windows))]
    {
        let _ = domain;
        false
    }
}

fn forward_upstream(
    upstream: &Mutex<UdpSocket>,
    resp: &mut [u8],
    packet: &[u8],
) -> Option<Vec<u8>> {
    if packet.len() < 2 {
        return None;
    }
    let want_id = (packet[0], packet[1]);
    let sock = upstream.lock();

    for server in [PRIMARY_UPSTREAM, FALLBACK_UPSTREAM] {
        if sock.send_to(packet, server).is_err() {
            continue;
        }
        let deadline = std::time::Instant::now() + Duration::from_millis(1200);
        while std::time::Instant::now() < deadline {
            match sock.recv_from(resp) {
                Ok((n, _)) if n >= 2 && resp[0] == want_id.0 && resp[1] == want_id.1 => {
                    return Some(resp[..n].to_vec());
                }
                Ok(_) => continue,
                Err(_) => break,
            }
        }
    }
    None
}

fn build_query_a(name: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(64);
    out.extend_from_slice(&[0x12, 0x34]); // TXID
    out.extend_from_slice(&[0x01, 0x00]); // standard query, recursion desired
    out.extend_from_slice(&[0x00, 0x01]); // QDCOUNT 1
    out.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
    for label in name.split('.') {
        let bytes = label.as_bytes();
        out.push(bytes.len() as u8);
        out.extend_from_slice(bytes);
    }
    out.push(0);
    out.extend_from_slice(&[0x00, 0x01]); // TYPE A
    out.extend_from_slice(&[0x00, 0x01]); // CLASS IN
    out
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn extract_qname(packet: &[u8]) -> Option<String> {
    if packet.len() < 12 {
        return None;
    }
    let qdcount = u16::from_be_bytes([packet[4], packet[5]]);
    if qdcount == 0 {
        return None;
    }

    let mut i = 12usize;
    let mut labels = Vec::new();
    loop {
        if i >= packet.len() {
            return None;
        }
        let len = packet[i] as usize;
        if len == 0 {
            break;
        }
        if len >= 0xC0 {
            return None;
        }
        i += 1;
        if i + len > packet.len() {
            return None;
        }
        let label = std::str::from_utf8(&packet[i..i + len]).ok()?;
        labels.push(label.to_ascii_lowercase());
        i += len;
    }
    if labels.is_empty() {
        return None;
    }
    Some(labels.join("."))
}

fn build_nxdomain(request: &[u8]) -> Option<Vec<u8>> {
    build_dns_error(request, 0x83)
}

fn build_servfail(request: &[u8]) -> Option<Vec<u8>> {
    build_dns_error(request, 0x82)
}

fn build_dns_error(request: &[u8], rcode_flags: u8) -> Option<Vec<u8>> {
    if request.len() < 12 {
        return None;
    }
    let mut response = request.to_vec();
    response[2] = 0x81;
    response[3] = rcode_flags;
    response[6] = 0;
    response[7] = 0;
    response[8] = 0;
    response[9] = 0;
    response[10] = 0;
    response[11] = 0;
    let qend = skip_question(request)?;
    response.truncate(qend);
    Some(response)
}

fn skip_question(packet: &[u8]) -> Option<usize> {
    let mut i = 12usize;
    while i < packet.len() {
        let len = packet[i] as usize;
        if len == 0 {
            i += 1;
            break;
        }
        if len >= 0xC0 {
            i += 2;
            break;
        }
        i += 1 + len;
    }
    if i + 4 > packet.len() {
        return None;
    }
    Some(i + 4)
}
