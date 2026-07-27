use std::collections::HashSet;
use std::env;
use std::fs;
use std::hash::{Hash, Hasher};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::collections::hash_map::DefaultHasher;

const SOURCES: &[(&str, &str)] = &[
    (
        "stevenblack-gambling-porn.hosts",
        "https://raw.githubusercontent.com/StevenBlack/hosts/master/alternates/gambling-porn/hosts",
    ),
    (
        "blocklistproject-porn.txt",
        "https://raw.githubusercontent.com/blocklistproject/Lists/master/porn.txt",
    ),
    (
        "blocklistproject-gambling.txt",
        "https://raw.githubusercontent.com/blocklistproject/Lists/master/gambling.txt",
    ),
];

const MAGIC: &[u8; 4] = b"WBLM";
const VERSION: u32 = 1;
const FALSE_POSITIVE_RATE: f64 = 0.001;

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=scripts/firewall_rules.bat");
    println!("cargo:rerun-if-changed=scripts/firewall_rules_off.bat");
    println!("cargo:rerun-if-changed=scripts/disable_vpn_adapters.bat");
    println!("cargo:rerun-if-changed=scripts/disable_vpn_adapters.ps1");
    println!("cargo:rerun-if-env-changed=WARDEN_BLOCKLIST_CACHE");

    match build_bloom_artifact() {
        Ok(stats) => {
            println!(
                "cargo:warning=Warden bloom filter ready: {} domains, {} bits, {} hashes",
                stats.domains, stats.bits, stats.hashes
            );
        }
        Err(error) => {
            panic!("Failed to build Warden blocklist bloom filter: {error}");
        }
    }

    tauri_build::build();
}

struct BloomStats {
    domains: u64,
    bits: u64,
    hashes: u32,
}

fn build_bloom_artifact() -> Result<BloomStats, Box<dyn std::error::Error>> {
    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR")?);
    let cache_dir = env::var("WARDEN_BLOCKLIST_CACHE")
        .map(PathBuf::from)
        .unwrap_or_else(|_| manifest_dir.join("blocklists").join("cache"));
    fs::create_dir_all(&cache_dir)?;

    let mut domains = HashSet::new();
    for (filename, url) in SOURCES {
        let path = cache_dir.join(filename);
        ensure_cached(&path, url)?;
        let text = fs::read_to_string(&path)?;
        parse_domains(&text, &mut domains);
    }

    if domains.is_empty() {
        return Err("no domains parsed from blocklist sources".into());
    }

    let n = domains.len() as f64;
    let m = optimal_bits(n, FALSE_POSITIVE_RATE);
    let k = optimal_hashes(m, n);
    let mut filter = BloomBuilder::new(m, k);
    for domain in &domains {
        filter.insert(domain);
    }

    let out_dir = PathBuf::from(env::var("OUT_DIR")?);
    let bloom_path = out_dir.join("blocklist.bloom");
    filter.write_to(&bloom_path, domains.len() as u64)?;

    // Also keep a copy next to sources for inspection / offline tooling.
    let generated = manifest_dir.join("blocklists").join("generated");
    fs::create_dir_all(&generated)?;
    fs::copy(&bloom_path, generated.join("blocklist.bloom"))?;
    fs::write(
        generated.join("stats.json"),
        format!(
            "{{\n  \"domains\": {},\n  \"bits\": {},\n  \"hashes\": {},\n  \"false_positive_rate\": {}\n}}\n",
            domains.len(),
            m,
            k,
            FALSE_POSITIVE_RATE
        ),
    )?;

    Ok(BloomStats {
        domains: domains.len() as u64,
        bits: m,
        hashes: k,
    })
}

fn ensure_cached(path: &Path, url: &str) -> Result<(), Box<dyn std::error::Error>> {
    if path.exists() && path.metadata()?.len() > 0 {
        println!("cargo:warning=Using cached blocklist {}", path.display());
        return Ok(());
    }

    println!("cargo:warning=Fetching blocklist (build-time only): {url}");
    let response = ureq::get(url)
        .set("User-Agent", "Warden-Build/0.1 (compile-time blocklist fetch)")
        .call()
        .map_err(|e| format!("download failed for {url}: {e}"))?;

    let mut body = String::new();
    response
        .into_reader()
        .take(80 * 1024 * 1024)
        .read_to_string(&mut body)?;

    if body.trim().is_empty() {
        return Err(format!("empty response from {url}").into());
    }

    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let mut file = fs::File::create(path)?;
    file.write_all(body.as_bytes())?;
    Ok(())
}

fn parse_domains(text: &str, out: &mut HashSet<String>) {
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with('!') {
            continue;
        }

        let mut parts = line.split_whitespace();
        let first = match parts.next() {
            Some(v) => v,
            None => continue,
        };

        let candidate = if looks_like_ip(first) {
            match parts.next() {
                Some(host) => host,
                None => continue,
            }
        } else {
            first
        };

        if let Some(domain) = normalize_domain(candidate) {
            out.insert(domain);
        }
    }
}

fn looks_like_ip(value: &str) -> bool {
    value.parse::<std::net::Ipv4Addr>().is_ok() || value.parse::<std::net::Ipv6Addr>().is_ok()
}

fn normalize_domain(raw: &str) -> Option<String> {
    let mut value = raw.trim().trim_matches('.').to_ascii_lowercase();
    if value.is_empty() {
        return None;
    }
    if let Some(stripped) = value.strip_prefix("||") {
        value = stripped
            .trim_end_matches('^')
            .trim_matches('.')
            .to_string();
    }
    if value.contains('/') || value.contains('*') || value.contains(' ') {
        return None;
    }
    if !value.contains('.') && value != "localhost" {
        return None;
    }
    if value.starts_with('.') || value.ends_with('.') {
        return None;
    }
    if !value
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '.')
    {
        return None;
    }
    Some(value)
}

fn optimal_bits(n: f64, p: f64) -> u64 {
    let m = -(n * p.ln()) / (std::f64::consts::LN_2 * std::f64::consts::LN_2);
    m.ceil().max(64.0) as u64
}

fn optimal_hashes(m: u64, n: f64) -> u32 {
    let k = (m as f64 / n) * std::f64::consts::LN_2;
    k.round().clamp(1.0, 16.0) as u32
}

struct BloomBuilder {
    bits: Vec<u8>,
    bit_len: u64,
    hashes: u32,
}

impl BloomBuilder {
    fn new(bit_len: u64, hashes: u32) -> Self {
        let bytes = ((bit_len + 7) / 8) as usize;
        Self {
            bits: vec![0u8; bytes],
            bit_len,
            hashes,
        }
    }

    fn insert(&mut self, item: &str) {
        for i in 0..self.hashes {
            let idx = self.bit_index(item, i);
            let byte = (idx / 8) as usize;
            let bit = (idx % 8) as u8;
            self.bits[byte] |= 1 << bit;
        }
    }

    fn bit_index(&self, item: &str, i: u32) -> u64 {
        let mut h1 = DefaultHasher::new();
        item.hash(&mut h1);
        0u64.hash(&mut h1);
        let a = h1.finish();

        let mut h2 = DefaultHasher::new();
        item.hash(&mut h2);
        1u64.hash(&mut h2);
        let b = h2.finish().max(1);

        let mixed = a.wrapping_add((i as u64).wrapping_mul(b));
        mixed % self.bit_len
    }

    fn write_to(&self, path: &Path, domain_count: u64) -> Result<(), Box<dyn std::error::Error>> {
        let mut file = fs::File::create(path)?;
        file.write_all(MAGIC)?;
        file.write_all(&VERSION.to_le_bytes())?;
        file.write_all(&self.bit_len.to_le_bytes())?;
        file.write_all(&self.hashes.to_le_bytes())?;
        file.write_all(&domain_count.to_le_bytes())?;
        file.write_all(&self.bits)?;
        Ok(())
    }
}
