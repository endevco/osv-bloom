//! Wire format and bloom-filter implementation for `osv-bloom`.
//!
//! The filter stores a set of `(npm package name, semver major bucket)`
//! pairs drawn from OSV `MAL-*` advisories. Consumers probe it during
//! lockfile-driven installs to skip the live-API hit for the >99% of
//! installs that touch nothing flagged.
//!
//! Wire format (little-endian, 64-byte header + bitset):
//!
//! ```text
//! offset  size  field
//! 0       4     magic = b"OSVB"
//! 4       4     format_version (u32) = 1
//! 8       8     m  (u64) — bit count
//! 16      4     k  (u32) — hash count
//! 20      4     n  (u32) — entries inserted
//! 24      8     built_at_unix_seconds (u64)
//! 32      32    seed (BLAKE3 keyed-hash key)
//! 64      ceil(m/8)  bitset
//! ```
//!
//! Hashing: a keyed BLAKE3 over `name || 0x00 || bucket`. The 32-byte
//! digest is split into two `u64`s `(h1, h2)`; bit indices are
//! `(h1 + i*h2) mod m` for `i in 0..k` (Kirsch–Mitzenmacher double
//! hashing). Wrap-around is intentional — `u64` arithmetic before the
//! modulo cannot overflow the bit space we use.
//!
//! Bucket encoding for a parsed semver:
//! - `major >= 1`  → `"<major>"`            (e.g. `"3"` for `3.7.1`)
//! - `major == 0`  → `"0.<minor>"`          (e.g. `"0.3"` for `0.3.7`,
//!                                           since pre-1.0 semver treats
//!                                           every minor as breaking)
//! - wildcard      → `"*"`                  (advisory covers all versions
//!                                           or range is unbounded)

#![forbid(unsafe_code)]

pub const MAGIC: &[u8; 4] = b"OSVB";
pub const FORMAT_VERSION: u32 = 1;
pub const HEADER_LEN: usize = 64;

#[derive(Debug, thiserror::Error)]
pub enum DecodeError {
    #[error("buffer shorter than 64-byte header")]
    TooShort,
    #[error("bad magic: expected b\"OSVB\"")]
    BadMagic,
    #[error("unsupported format version {0}, this build understands {FORMAT_VERSION}")]
    UnsupportedVersion(u32),
    #[error("declared bit count m={m} requires {needed} bitset bytes, only {got} present")]
    TruncatedBitset { m: u64, needed: usize, got: usize },
    #[error("nonsensical params: m={0}, k={1}")]
    BadParams(u64, u32),
}

/// Owned, decoded filter — used for probing.
#[derive(Clone)]
pub struct Bloom {
    m: u64,
    k: u32,
    n: u32,
    built_at: u64,
    seed: [u8; 32],
    bits: Box<[u8]>,
}

impl Bloom {
    /// Allocate an empty filter sized for `expected_entries` at the
    /// given false-positive rate. `m` is rounded up to a multiple of 8
    /// so the bitset is byte-aligned.
    pub fn new(expected_entries: u64, false_positive_rate: f64, seed: [u8; 32]) -> Self {
        assert!(false_positive_rate > 0.0 && false_positive_rate < 1.0);
        let n = expected_entries.max(1) as f64;
        let ln2_sq = std::f64::consts::LN_2 * std::f64::consts::LN_2;
        let m_exact = -(n * false_positive_rate.ln()) / ln2_sq;
        let m = ((m_exact.ceil() as u64).max(64) + 7) / 8 * 8;
        let k = ((m as f64 / n) * std::f64::consts::LN_2).round() as u32;
        let k = k.clamp(1, 32);
        Self {
            m,
            k,
            n: 0,
            built_at: 0,
            seed,
            bits: vec![0u8; (m / 8) as usize].into_boxed_slice(),
        }
    }

    pub fn set_built_at(&mut self, built_at_unix_seconds: u64) {
        self.built_at = built_at_unix_seconds;
    }

    pub fn m(&self) -> u64 { self.m }
    pub fn k(&self) -> u32 { self.k }
    pub fn n(&self) -> u32 { self.n }
    pub fn built_at(&self) -> u64 { self.built_at }
    pub fn seed(&self) -> &[u8; 32] { &self.seed }
    pub fn byte_len(&self) -> usize { HEADER_LEN + self.bits.len() }

    /// Insert a `(name, bucket)` pair. Re-inserts are cheap (idempotent).
    pub fn insert(&mut self, name: &str, bucket: &str) {
        let (h1, h2) = self.hash(name, bucket);
        let mut newly_set = false;
        for i in 0..self.k {
            let idx = (h1.wrapping_add((i as u64).wrapping_mul(h2)) % self.m) as usize;
            let byte = &mut self.bits[idx / 8];
            let mask = 1u8 << (idx % 8);
            if *byte & mask == 0 {
                *byte |= mask;
                newly_set = true;
            }
        }
        // Approximate `n` by counting first-time inserts. Good enough
        // for the manifest; the bloom's correctness doesn't depend on
        // it being exact.
        if newly_set {
            self.n = self.n.saturating_add(1);
        }
    }

    /// `true` if the pair *may* be present, `false` if definitely absent.
    pub fn contains(&self, name: &str, bucket: &str) -> bool {
        let (h1, h2) = self.hash(name, bucket);
        for i in 0..self.k {
            let idx = (h1.wrapping_add((i as u64).wrapping_mul(h2)) % self.m) as usize;
            let byte = self.bits[idx / 8];
            let mask = 1u8 << (idx % 8);
            if byte & mask == 0 {
                return false;
            }
        }
        true
    }

    fn hash(&self, name: &str, bucket: &str) -> (u64, u64) {
        let mut hasher = blake3::Hasher::new_keyed(&self.seed);
        hasher.update(name.as_bytes());
        hasher.update(&[0u8]);
        hasher.update(bucket.as_bytes());
        let digest = hasher.finalize();
        let bytes = digest.as_bytes();
        let h1 = u64::from_le_bytes(bytes[0..8].try_into().expect("32-byte digest"));
        let h2 = u64::from_le_bytes(bytes[8..16].try_into().expect("32-byte digest"));
        (h1, h2)
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.byte_len());
        out.extend_from_slice(MAGIC);
        out.extend_from_slice(&FORMAT_VERSION.to_le_bytes());
        out.extend_from_slice(&self.m.to_le_bytes());
        out.extend_from_slice(&self.k.to_le_bytes());
        out.extend_from_slice(&self.n.to_le_bytes());
        out.extend_from_slice(&self.built_at.to_le_bytes());
        out.extend_from_slice(&self.seed);
        out.extend_from_slice(&self.bits);
        debug_assert_eq!(out.len(), self.byte_len());
        out
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        if bytes.len() < HEADER_LEN {
            return Err(DecodeError::TooShort);
        }
        if &bytes[0..4] != MAGIC {
            return Err(DecodeError::BadMagic);
        }
        let format_version = u32::from_le_bytes(bytes[4..8].try_into().unwrap());
        if format_version != FORMAT_VERSION {
            return Err(DecodeError::UnsupportedVersion(format_version));
        }
        let m = u64::from_le_bytes(bytes[8..16].try_into().unwrap());
        let k = u32::from_le_bytes(bytes[16..20].try_into().unwrap());
        let n = u32::from_le_bytes(bytes[20..24].try_into().unwrap());
        let built_at = u64::from_le_bytes(bytes[24..32].try_into().unwrap());
        if m == 0 || m % 8 != 0 || k == 0 {
            return Err(DecodeError::BadParams(m, k));
        }
        let mut seed = [0u8; 32];
        seed.copy_from_slice(&bytes[32..64]);
        let needed = (m / 8) as usize;
        let got = bytes.len() - HEADER_LEN;
        if got < needed {
            return Err(DecodeError::TruncatedBitset { m, needed, got });
        }
        let bits = bytes[HEADER_LEN..HEADER_LEN + needed]
            .to_vec()
            .into_boxed_slice();
        Ok(Self { m, k, n, built_at, seed, bits })
    }
}

/// Encode a semver triple as the bucket string used in keys.
///
/// `major >= 1`  → `"<major>"`
/// `major == 0`  → `"0.<minor>"`
pub fn bucket(major: u64, minor: u64) -> String {
    if major == 0 {
        format!("0.{minor}")
    } else {
        major.to_string()
    }
}

pub const WILDCARD_BUCKET: &str = "*";

/// Deterministic seed shared by every v1 filter. The bloom seed is
/// part of the format contract — changing it invalidates every
/// previously-cached client until they refetch. If you need a
/// different seed, bump `FORMAT_VERSION`.
pub fn default_seed() -> [u8; 32] {
    *blake3::hash(b"osv-bloom v1 deterministic seed").as_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn seed() -> [u8; 32] {
        let mut s = [0u8; 32];
        for (i, b) in s.iter_mut().enumerate() {
            *b = i as u8;
        }
        s
    }

    #[test]
    fn insert_then_contains_is_true() {
        let mut b = Bloom::new(1000, 0.001, seed());
        b.insert("evil-pkg", "1");
        b.insert("evil-pkg", "2");
        b.insert("good-pkg", "0.3");
        assert!(b.contains("evil-pkg", "1"));
        assert!(b.contains("evil-pkg", "2"));
        assert!(b.contains("good-pkg", "0.3"));
    }

    #[test]
    fn contains_returns_false_for_unseen() {
        let mut b = Bloom::new(1000, 0.001, seed());
        b.insert("evil-pkg", "1");
        // We can't assert "false" universally (bloom can FP), but with
        // 0.1% FPR and a single insert the bit density is tiny enough
        // that these specific other keys won't collide.
        assert!(!b.contains("evil-pkg", "2"));
        assert!(!b.contains("other-pkg", "1"));
    }

    #[test]
    fn encode_decode_roundtrip_preserves_membership() {
        let mut b = Bloom::new(1000, 0.001, seed());
        b.set_built_at(1_715_000_000);
        for i in 0..100 {
            b.insert(&format!("pkg-{i}"), &bucket(i % 5, i % 4));
        }
        let bytes = b.encode();
        let decoded = Bloom::decode(&bytes).expect("decode");
        assert_eq!(decoded.m(), b.m());
        assert_eq!(decoded.k(), b.k());
        assert_eq!(decoded.n(), b.n());
        assert_eq!(decoded.built_at(), 1_715_000_000);
        for i in 0..100 {
            assert!(decoded.contains(&format!("pkg-{i}"), &bucket(i % 5, i % 4)));
        }
    }

    #[test]
    fn decode_rejects_bad_magic() {
        let mut bytes = Bloom::new(10, 0.01, seed()).encode();
        bytes[0] = b'X';
        assert!(matches!(Bloom::decode(&bytes), Err(DecodeError::BadMagic)));
    }

    #[test]
    fn decode_rejects_truncated_bitset() {
        let bytes = Bloom::new(10, 0.01, seed()).encode();
        let truncated = &bytes[..bytes.len() - 1];
        assert!(matches!(
            Bloom::decode(truncated),
            Err(DecodeError::TruncatedBitset { .. })
        ));
    }

    #[test]
    fn observed_fpr_under_target() {
        // Insert 10k entries at target FPR 1% and check that random
        // never-inserted lookups stay near or below the target. This
        // is a sanity check on params + hash distribution, not a tight
        // bound.
        let target = 0.01;
        let mut b = Bloom::new(10_000, target, seed());
        for i in 0..10_000 {
            b.insert(&format!("inserted-{i}"), "1");
        }
        let mut fp = 0usize;
        let probes = 20_000;
        for i in 0..probes {
            if b.contains(&format!("missing-{i}"), "1") {
                fp += 1;
            }
        }
        let observed = fp as f64 / probes as f64;
        assert!(
            observed < target * 2.0,
            "observed FPR {observed} exceeded 2x target {target}"
        );
    }

    #[test]
    fn bucket_encodes_zero_major_with_minor() {
        assert_eq!(bucket(0, 3), "0.3");
        assert_eq!(bucket(0, 0), "0.0");
        assert_eq!(bucket(1, 2), "1");
        assert_eq!(bucket(42, 0), "42");
    }
}
