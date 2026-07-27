//! Dual-lookup engine: finance bypass → SQLite custom → baked Bloom filter.

use crate::bloom::BloomFilter;
use crate::bypass::is_finance_bypass;
use crate::db::Db;
use serde::Serialize;
use std::sync::Arc;

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum BlockSource {
    Custom,
    Bloom,
    Bypass,
    None,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LookupResult {
    pub domain: String,
    pub blocked: bool,
    pub source: BlockSource,
}

pub struct LookupEngine {
    db: Arc<Db>,
    bloom: BloomFilter,
}

impl LookupEngine {
    pub fn new(db: Arc<Db>, bloom: BloomFilter) -> Self {
        Self { db, bloom }
    }

    pub fn bloom_domain_count(&self) -> u64 {
        self.bloom.domain_count
    }

    pub fn normalize_input(raw: &str) -> Result<String, String> {
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            return Err("domain is empty".into());
        }

        let mut value = trimmed.to_ascii_lowercase();
        if let Some(rest) = value.strip_prefix("http://") {
            value = rest.to_string();
        } else if let Some(rest) = value.strip_prefix("https://") {
            value = rest.to_string();
        }

        if let Some((host, _)) = value.split_once('/') {
            value = host.to_string();
        }
        if let Some((host, _)) = value.split_once('?') {
            value = host.to_string();
        }
        if let Some((host, _)) = value.split_once('#') {
            value = host.to_string();
        }
        if let Some(rest) = value.strip_prefix('[') {
            if let Some(end) = rest.find(']') {
                value = rest[..end].to_string();
            }
        } else if let Some((host, port)) = value.rsplit_once(':') {
            // Keep IPv4 as-is; only strip :port from hostnames.
            if !is_ipv4_literal(host) && port.chars().all(|c| c.is_ascii_digit()) {
                value = host.to_string();
            }
        }

        value = value.trim_matches('.').to_string();
        if value.starts_with("www.") {
            value = value.trim_start_matches("www.").to_string();
        }

        if is_ipv4_literal(&value) {
            return Ok(value);
        }

        if value.is_empty() || !value.contains('.') {
            return Err("enter a domain (example.com) or IPv4 (1.2.3.4)".into());
        }
        if !value
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '.')
        {
            return Err("domain contains invalid characters".into());
        }
        Ok(value)
    }

    /// Parent hosts to evaluate. Never includes bare TLDs (`com`, `pk`, …).
    /// IPv4 literals are exact-only (no octet "parents").
    pub fn candidates(domain: &str) -> Vec<String> {
        let current = domain.to_ascii_lowercase();
        if is_ipv4_literal(&current) {
            return vec![current];
        }
        let mut out = Vec::new();
        let mut current = current;
        loop {
            if current.contains('.') {
                out.push(current.clone());
            }
            match current.split_once('.') {
                Some((_, rest)) if rest.contains('.') => {
                    current = rest.to_string();
                }
                _ => break,
            }
        }
        out
    }

    pub fn lookup(&self, raw_domain: &str) -> LookupResult {
        let domain = match Self::normalize_input(raw_domain) {
            Ok(v) => v,
            Err(_) => {
                return LookupResult {
                    domain: raw_domain.to_string(),
                    blocked: false,
                    source: BlockSource::None,
                };
            }
        };

        let candidates = Self::candidates(&domain);

        // 1) Custom blocklist always wins (including over finance/infra allow).
        for candidate in &candidates {
            if self.db.contains_custom_exact(candidate).unwrap_or(false) {
                return LookupResult {
                    domain,
                    blocked: true,
                    source: BlockSource::Custom,
                };
            }
        }

        // 2) Banking / payments / infra allow — skip Bloom only.
        if is_finance_bypass(&domain) {
            return LookupResult {
                domain,
                blocked: false,
                source: BlockSource::Bypass,
            };
        }
        for candidate in &candidates {
            if is_finance_bypass(candidate) {
                return LookupResult {
                    domain,
                    blocked: false,
                    source: BlockSource::Bypass,
                };
            }
        }

        // 3) Bloom
        for candidate in &candidates {
            if self.bloom.may_contain(candidate) {
                return LookupResult {
                    domain,
                    blocked: true,
                    source: BlockSource::Bloom,
                };
            }
        }

        LookupResult {
            domain,
            blocked: false,
            source: BlockSource::None,
        }
    }
}

fn is_ipv4_literal(value: &str) -> bool {
    value.parse::<std::net::Ipv4Addr>().is_ok()
}
