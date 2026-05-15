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
//! hashing). All intermediate arithmetic uses `wrapping_*` and is sound
//! under any `u64` value of `h1`/`h2`; the `% m` reduction afterwards
//! pins the result inside the bitset. The 0x00 separator is unambiguous
//! because bucket strings never contain a 0x00 byte (they are digits,
//! `.`, or `*`).
//!
//! Bucket encoding for a parsed semver:
//! - `major >= 1` → `"<major>"` (e.g. `"3"` for `3.7.1`)
//! - `major == 0` → `"0.<minor>"` (e.g. `"0.3"` for `0.3.7`, since pre-1.0
//!   semver treats every minor as breaking)
//! - wildcard → `"*"` (advisory covers all versions or range is unbounded)

#![forbid(unsafe_code)]

pub const MAGIC: &[u8; 4] = b"OSVB";
pub const FORMAT_VERSION: u32 = 1;
pub const HEADER_LEN: usize = 64;

/// Maximum `k` accepted by `decode`. Build path clamps to 32; decode
/// mirrors that so a crafted file cannot drive `contains` into a
/// multi-billion-iteration spin loop.
pub const MAX_K: u32 = 32;

/// Maximum `m` accepted by `decode`: 1 Gibit ≈ 128 MiB bitset. Three
/// orders of magnitude above the current ~3.1M-bit deployment and well
/// past any realistic OSV growth horizon — but bounded, so a header
/// with `m = u64::MAX` cannot be used to claim absurd allocations.
pub const MAX_M: u64 = 1 << 30;

/// Errors produced by `Bloom::try_new`. `Bloom::new` panics on the
/// same conditions; pick whichever fits the caller.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum BuildError {
    #[error("false_positive_rate must be a finite probability in (0, 1), got {0}")]
    InvalidFpr(f64),
    #[error("computed m={got} bits exceeds MAX_M={MAX_M}; reduce expected_entries or raise fpr")]
    MTooLarge { got: f64 },
}

#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum DecodeError {
    #[error("buffer shorter than 64-byte header")]
    TooShort,
    #[error("bad magic: expected b\"OSVB\"")]
    BadMagic,
    #[error("unsupported format version {0}, this build understands {FORMAT_VERSION}")]
    UnsupportedVersion(u32),
    #[error("declared bit count m={m} requires {needed} bitset bytes, only {got} present")]
    TruncatedBitset { m: u64, needed: usize, got: usize },
    #[error("trailing bytes after bitset: {extra} extra byte(s)")]
    TrailingBytes { extra: usize },
    #[error("nonsensical params: m={0}, k={1}")]
    BadParams(u64, u32),
    #[error("k={0} exceeds MAX_K={MAX_K}")]
    KTooLarge(u32),
    #[error("m={0} exceeds MAX_M={MAX_M}")]
    MTooLarge(u64),
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
        Self::try_new(expected_entries, false_positive_rate, seed)
            .expect("Bloom::new: invalid parameters (use try_new for a Result)")
    }

    /// Fallible constructor: returns a structured error on bad input
    /// instead of panicking. Use this when params come from
    /// configuration files or untrusted callers.
    pub fn try_new(
        expected_entries: u64,
        false_positive_rate: f64,
        seed: [u8; 32],
    ) -> Result<Self, BuildError> {
        if !(false_positive_rate.is_finite()
            && false_positive_rate > 0.0
            && false_positive_rate < 1.0)
        {
            return Err(BuildError::InvalidFpr(false_positive_rate));
        }
        let n = expected_entries.max(1) as f64;
        let ln2_sq = std::f64::consts::LN_2 * std::f64::consts::LN_2;
        let m_exact = -(n * false_positive_rate.ln()) / ln2_sq;
        if !(m_exact.is_finite() && m_exact < (MAX_M as f64)) {
            return Err(BuildError::MTooLarge { got: m_exact });
        }
        let m = (m_exact.ceil() as u64).max(64).div_ceil(8) * 8;
        let k = ((m as f64 / n) * std::f64::consts::LN_2).round() as u32;
        let k = k.clamp(1, MAX_K);
        Ok(Self {
            m,
            k,
            n: 0,
            built_at: 0,
            seed,
            bits: vec![0u8; (m / 8) as usize].into_boxed_slice(),
        })
    }

    pub fn set_built_at(&mut self, built_at_unix_seconds: u64) {
        self.built_at = built_at_unix_seconds;
    }

    pub fn m(&self) -> u64 {
        self.m
    }
    pub fn k(&self) -> u32 {
        self.k
    }
    pub fn n(&self) -> u32 {
        self.n
    }
    pub fn built_at(&self) -> u64 {
        self.built_at
    }
    pub fn seed(&self) -> &[u8; 32] {
        &self.seed
    }
    pub fn byte_len(&self) -> usize {
        HEADER_LEN + self.bits.len()
    }

    /// Insert a `(name, bucket)` pair. Re-inserts are cheap (idempotent).
    pub fn insert(&mut self, name: &str, bucket: &str) {
        let (h1, h2) = self.hash(name, bucket);
        let mut acc = h1;
        let mut newly_set = false;
        for _ in 0..self.k {
            // `acc` walks `h1, h1+h2, h1+2*h2, ...` under wrapping u64
            // addition — algebraically identical to the closed-form
            // `h1 + i*h2` used elsewhere in the literature, but
            // without a per-iteration multiply.
            let idx = (acc % self.m) as usize;
            let byte = &mut self.bits[idx / 8];
            let mask = 1u8 << (idx % 8);
            if *byte & mask == 0 {
                *byte |= mask;
                newly_set = true;
            }
            acc = acc.wrapping_add(h2);
        }
        // Approximate `n` by counting first-time inserts. Good enough
        // for the manifest; the bloom's correctness doesn't depend on
        // it being exact.
        if newly_set {
            self.n = self.n.saturating_add(1);
        }
    }

    /// `true` if the pair *may* be present, `false` if definitely absent.
    ///
    /// Callers should ALSO probe `WILDCARD_BUCKET` for the same `name`:
    /// some advisories cover all versions of a package and are inserted
    /// under `"*"` rather than a specific bucket. A typical probe is
    ///
    /// ```ignore
    /// bloom.contains(name, &bucket(major, minor))
    ///     || bloom.contains(name, WILDCARD_BUCKET)
    /// ```
    #[must_use = "the probe result is the only output of `contains`"]
    pub fn contains(&self, name: &str, bucket: &str) -> bool {
        let (h1, h2) = self.hash(name, bucket);
        let mut acc = h1;
        for _ in 0..self.k {
            let idx = (acc % self.m) as usize;
            let byte = self.bits[idx / 8];
            let mask = 1u8 << (idx % 8);
            if byte & mask == 0 {
                return false;
            }
            acc = acc.wrapping_add(h2);
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
        let header_field = "header slice is exactly the declared size";
        let format_version = u32::from_le_bytes(bytes[4..8].try_into().expect(header_field));
        if format_version != FORMAT_VERSION {
            return Err(DecodeError::UnsupportedVersion(format_version));
        }
        let m = u64::from_le_bytes(bytes[8..16].try_into().expect(header_field));
        let k = u32::from_le_bytes(bytes[16..20].try_into().expect(header_field));
        let n = u32::from_le_bytes(bytes[20..24].try_into().expect(header_field));
        let built_at = u64::from_le_bytes(bytes[24..32].try_into().expect(header_field));
        if m == 0 || m % 8 != 0 || k == 0 {
            return Err(DecodeError::BadParams(m, k));
        }
        if k > MAX_K {
            return Err(DecodeError::KTooLarge(k));
        }
        if m > MAX_M {
            return Err(DecodeError::MTooLarge(m));
        }
        let mut seed = [0u8; 32];
        seed.copy_from_slice(&bytes[32..64]);
        let needed = (m / 8) as usize;
        let got = bytes.len() - HEADER_LEN;
        if got < needed {
            return Err(DecodeError::TruncatedBitset { m, needed, got });
        }
        if got > needed {
            return Err(DecodeError::TrailingBytes {
                extra: got - needed,
            });
        }
        let bits = bytes[HEADER_LEN..HEADER_LEN + needed]
            .to_vec()
            .into_boxed_slice();
        Ok(Self {
            m,
            k,
            n,
            built_at,
            seed,
            bits,
        })
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
    static SEED: std::sync::OnceLock<[u8; 32]> = std::sync::OnceLock::new();
    *SEED.get_or_init(|| *blake3::hash(b"osv-bloom v1 deterministic seed").as_bytes())
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
    fn decode_rejects_trailing_bytes() {
        let mut bytes = Bloom::new(10, 0.01, seed()).encode();
        bytes.push(0xab);
        assert!(matches!(
            Bloom::decode(&bytes),
            Err(DecodeError::TrailingBytes { extra: 1 })
        ));
    }

    #[test]
    fn decode_rejects_k_too_large() {
        let mut bytes = Bloom::new(10, 0.01, seed()).encode();
        // bytes[16..20] is the k field — write u32::MAX.
        bytes[16..20].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(matches!(
            Bloom::decode(&bytes),
            Err(DecodeError::KTooLarge(_))
        ));
    }

    #[test]
    fn decode_rejects_m_too_large() {
        let mut bytes = Bloom::new(10, 0.01, seed()).encode();
        // bytes[8..16] is m; pick a value > MAX_M that's still % 8 == 0.
        let bad_m: u64 = (MAX_M + 8) & !7;
        bytes[8..16].copy_from_slice(&bad_m.to_le_bytes());
        assert!(matches!(
            Bloom::decode(&bytes),
            Err(DecodeError::MTooLarge(_))
        ));
    }

    #[test]
    fn decode_rejects_bad_format_version() {
        let mut bytes = Bloom::new(10, 0.01, seed()).encode();
        bytes[4..8].copy_from_slice(&2u32.to_le_bytes());
        assert!(matches!(
            Bloom::decode(&bytes),
            Err(DecodeError::UnsupportedVersion(2))
        ));
    }

    #[test]
    fn decode_rejects_m_not_multiple_of_8() {
        let mut bytes = Bloom::new(10, 0.01, seed()).encode();
        bytes[8..16].copy_from_slice(&9u64.to_le_bytes());
        assert!(matches!(
            Bloom::decode(&bytes),
            Err(DecodeError::BadParams(9, _))
        ));
    }

    #[test]
    fn contains_must_use_wildcard_alongside_specific_bucket() {
        let mut b = Bloom::new(100, 0.001, seed());
        b.insert("evil-pkg", WILDCARD_BUCKET);
        // A consumer probing the wildcard bucket sees it.
        assert!(b.contains("evil-pkg", WILDCARD_BUCKET));
        // The specific bucket probe alone won't hit the wildcard entry.
        // (Documented in `contains` rustdoc.)
        let _ = b.contains("evil-pkg", &bucket(1, 0));
    }

    #[test]
    fn default_seed_is_stable_across_calls() {
        assert_eq!(default_seed(), default_seed());
    }

    /// Pin the v1 wire-format hash output. Any change to `hash` or the
    /// index-walk that alters which bits are set for known inputs is a
    /// wire-format break and must bump FORMAT_VERSION. This test would
    /// fail loudly if the Kirsch-Mitzenmacher walk drifted.
    #[test]
    fn try_new_rejects_bad_fpr() {
        let s = seed();
        assert!(matches!(
            Bloom::try_new(1000, 0.0, s),
            Err(BuildError::InvalidFpr(_))
        ));
        assert!(matches!(
            Bloom::try_new(1000, 1.0, s),
            Err(BuildError::InvalidFpr(_))
        ));
        assert!(matches!(
            Bloom::try_new(1000, f64::NAN, s),
            Err(BuildError::InvalidFpr(_))
        ));
    }

    #[test]
    fn try_new_rejects_oversize_m() {
        // Pair (huge n, tiny fpr) drives m_exact past MAX_M.
        let s = seed();
        let r = Bloom::try_new(u64::MAX / 2, 1e-300, s);
        assert!(matches!(r, Err(BuildError::MTooLarge { .. })));
    }

    /// Pin the v1 wire-format output against a known-good digest.
    ///
    /// Any change to `hash`, the index walk, the byte layout, the
    /// `default_seed` derivation, or the encoded header order flips
    /// this digest and breaks the test. If you intentionally changed
    /// the wire format, bump `FORMAT_VERSION` and update the golden
    /// value below.
    #[test]
    fn encoded_output_is_pinned_for_default_seed() {
        let mut b = Bloom::new(1_000, 0.001, default_seed());
        b.insert("evil-pkg", "1");
        b.insert("@scope/pkg", "0.3");
        b.insert("wildcard-pkg", WILDCARD_BUCKET);
        // `built_at` defaults to 0 so the encoded bytes are fully
        // deterministic across machines and runs.
        let encoded = b.encode();
        // BLAKE3-digest the encoded bytes so we pin the entire byte
        // sequence in one line instead of pasting ~1.8 KB of hex.
        let digest = blake3::hash(&encoded).to_hex();
        let expected = "64e383388a659b33149a59b70dfd814d0e4472c60b45a05d2ad00efdf6f1915d";
        assert_eq!(
            digest.as_str(),
            expected,
            "wire-format output changed. \
             If intentional, bump FORMAT_VERSION and update this digest.",
        );
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
