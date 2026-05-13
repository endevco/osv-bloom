# osv-bloom

A small, cron-refreshed bloom filter of `(npm package name, semver major bucket)` pairs drawn from OSV `MAL-*` advisories — the malicious-package archive at <https://osv-vulnerabilities.storage.googleapis.com/npm/all.zip>.

Built so package managers (initially [aube](https://github.com/endevco/aube)) can probe every lockfile entry on every install for ~free, then escalate to OSV's live `/v1/querybatch` only on a bloom hit. False-positive rate is `0.1%`, so a typical lockfile of ~1000 packages will trigger zero or one live-API call per install in steady state.

## Consume

Two files in [`dist/`](./dist/) on `main`:

- [`dist/filter.bin`](./dist/filter.bin) — the bloom filter itself
- [`dist/manifest.json`](./dist/manifest.json) — params, timestamps, digests

Raw URLs (CDN-cached, `If-None-Match` for change detection):

```
https://raw.githubusercontent.com/endevco/osv-bloom/main/dist/filter.bin
https://raw.githubusercontent.com/endevco/osv-bloom/main/dist/manifest.json
```

Rust consumers can depend on the reader crate directly:

```toml
[dependencies]
osv-bloom = { git = "https://github.com/endevco/osv-bloom" }
```

```rust
use osv_bloom::{Bloom, bucket};

let bytes = std::fs::read("filter.bin")?;
let bloom = Bloom::decode(&bytes)?;

if bloom.contains("evil-pkg", &bucket(1, 0)) {
    // probable hit — escalate to OSV live API for the exact (name, version)
}
```

## Refresh cadence

GitHub Actions cron runs every 10 minutes. The workflow re-downloads `all.zip`, rebuilds the entry set, and only commits when the underlying `(name, bucket)` set actually changed (commit message: `chore: refresh filter (N entries, M advisories, set@<digest>)`). Most ticks produce no commit — OSV doesn't publish that fast.

## Key encoding

For each `affected[]` in a `MAL-*.json`:

1. Skip if `package.ecosystem != "npm"`.
2. If `affected.versions[]` is populated (typical for malicious uploads), parse each as semver and emit one bucket per version.
3. Else walk `affected.ranges[].events[]`:
   - `introduced: "0"` → emit the wildcard bucket `"*"` (matches any version of this package).
   - `introduced: "<semver>"` → emit that version's bucket.
   - `fixed` / `last_affected` → emit that bucket too (defensive).
4. If nothing parsed, emit `"*"`.

Bucket encoding:

| version            | bucket |
|--------------------|--------|
| `1.2.3`            | `"1"`  |
| `3.7.0`            | `"3"`  |
| `0.3.7`            | `"0.3"` |
| `0.0.1`            | `"0.0"` |
| _any version_      | `"*"`  |

Pre-1.0 packages bucket by `0.<minor>` because semver allows breaking changes between minors below 1.0 — bucketing by `0` alone would false-positive every install of any 0.x package that ever had a vuln.

## Wire format (v1)

Little-endian. 64-byte header + bitset.

```text
offset  size  field
0       4     magic = b"OSVB"
4       4     format_version (u32) = 1
8       8     m  (u64) — bit count
16      4     k  (u32) — hash count
20      4     n  (u32) — entries inserted
24      8     built_at_unix_seconds (u64)
32      32    seed (BLAKE3 keyed-hash key)
64      ceil(m/8)  bitset (LE bit order: bit i of byte j is mask `1 << (i % 8)`, byte j = i / 8)
```

Hashing: keyed BLAKE3 over `name || 0x00 || bucket`. The 32-byte digest is split into `h1 = u64::from_le_bytes(d[0..8])` and `h2 = u64::from_le_bytes(d[8..16])`. Bit indices are `(h1 + i*h2) mod m` for `i in 0..k` ([Kirsch–Mitzenmacher double hashing](https://www.eecs.harvard.edu/~michaelm/postscripts/rsa2008.pdf)).

The seed is deterministic and public (`blake3::hash(b"osv-bloom v1 deterministic seed")`); bloom hashing is not a cryptographic operation. If the seed ever needs to change, bump `format_version` — every deployed client has to refetch anyway.

## Output is deterministic

For a given input set, the output bytes are byte-identical across runs. That lets the workflow `git diff --quiet dist/filter.bin` to decide whether to commit, so the git history reflects real OSV changes and not just clock ticks.

The `built_at_unix_seconds` field changes every run, which would defeat the diff — but it's _inside_ the header, and the diff still picks up that the bitset is unchanged because most of the 380 KB is the bitset. The workflow's diff check trips on any byte change including the timestamp, which is conservative; if that ever becomes too noisy, we can split `dist/filter.bin` (bitset + bloom params, timestamp-free) from `dist/manifest.json` (built_at lives only here).

## Sizing

At the current OSV state (~212K MAL-* advisories, ~216K unique `(name, bucket)` pairs):

- `m` ≈ 3.1M bits
- `k` = 10
- Filter size: ~380 KB

Doubles linearly with entry count. Headroom is fine — even a 1M-entry world is ~1.8 MB.

## Build locally

```sh
cargo run --release -p osv-bloom-build -- --out-dir dist
```

Takes ~30s on a typical laptop, mostly downloading the 200 MB OSV zip.

## License

MIT.
