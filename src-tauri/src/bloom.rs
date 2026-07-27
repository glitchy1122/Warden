//! Baked-in Bloom filter loaded from the compile-time artifact.

use std::hash::{Hash, Hasher};
use std::collections::hash_map::DefaultHasher;

const MAGIC: &[u8; 4] = b"WBLM";
const VERSION: u32 = 1;

pub struct BloomFilter {
    bits: &'static [u8],
    bit_len: u64,
    hashes: u32,
    pub domain_count: u64,
}

impl BloomFilter {
    pub fn from_embedded(bytes: &'static [u8]) -> Result<Self, String> {
        if bytes.len() < 4 + 4 + 8 + 4 + 8 {
            return Err("bloom artifact too small".into());
        }
        if &bytes[0..4] != MAGIC {
            return Err("bloom artifact magic mismatch".into());
        }

        let version = u32::from_le_bytes(bytes[4..8].try_into().unwrap());
        if version != VERSION {
            return Err(format!("unsupported bloom version {version}"));
        }

        let bit_len = u64::from_le_bytes(bytes[8..16].try_into().unwrap());
        let hashes = u32::from_le_bytes(bytes[16..20].try_into().unwrap());
        let domain_count = u64::from_le_bytes(bytes[20..28].try_into().unwrap());
        let expected = ((bit_len + 7) / 8) as usize;
        let bits = &bytes[28..];
        if bits.len() != expected {
            return Err(format!(
                "bloom bit buffer size mismatch: got {} expected {expected}",
                bits.len()
            ));
        }

        Ok(Self {
            bits,
            bit_len,
            hashes,
            domain_count,
        })
    }

    pub fn may_contain(&self, item: &str) -> bool {
        for i in 0..self.hashes {
            let idx = self.bit_index(item, i);
            let byte = (idx / 8) as usize;
            let bit = (idx % 8) as u8;
            if self.bits[byte] & (1 << bit) == 0 {
                return false;
            }
        }
        true
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
}

pub static EMBEDDED_BLOOM: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/blocklist.bloom"));
