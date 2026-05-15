//! Downloads OSV's npm vulnerability dump, extracts the `MAL-*`
//! advisories, and writes `dist/filter.bin` + `dist/manifest.json`.
//!
//! Output is deterministic for a given input set: a constant seed
//! and sorted-and-deduped entry list mean the workflow only commits
//! when the underlying set of vulnerable `(name, major)` buckets
//! actually changed.

use std::collections::BTreeSet;
use std::fs;
use std::io::{Read, Write};
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, anyhow, bail};
use clap::Parser;
use osv_bloom::{Bloom, WILDCARD_BUCKET, bucket, default_seed};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

const OSV_NPM_ZIP_URL: &str = "https://osv-vulnerabilities.storage.googleapis.com/npm/all.zip";

/// Target false-positive rate. At the current OSV deployment
/// (~216k entries) this produces ~3.1M bits / ~380 KB; 10x headroom
/// (~2M entries) would be ~3.6 MB — well under any size budget.
const TARGET_FPR: f64 = 0.001;

/// Hard cap on the OSV zip download size. The live `npm/all.zip` is
/// ~200 MB as of this writing; 1 GiB gives ~5x headroom while
/// preventing an unbounded buffer from a hostile origin.
const MAX_DOWNLOAD_BYTES: u64 = 1 << 30;

/// Hard cap on each decompressed JSON advisory. Real entries are
/// single-digit kilobytes; 1 MiB is a comfortable ceiling that
/// neutralises decompression-bomb individual entries.
const MAX_ENTRY_BYTES: u64 = 1 << 20;

/// Overall HTTP timeout for the OSV download. reqwest applies this
/// end-to-end (connect, send, and the full body read), so it must be
/// wide enough to pull the ~200 MB zip over a slow CI link while still
/// firing before the 10-minute job-level timeout.
const HTTP_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(540);

/// Minimum number of entries we expect from a healthy OSV dump. If
/// the build produces fewer than this, something is wrong upstream
/// (schema change, empty zip, all-malformed JSON) and we refuse to
/// deploy rather than silently ship a filter that suppresses every
/// live-API escalation. Set well below current real value (~216k).
const MIN_ENTRIES: usize = 1_000;

#[derive(Parser)]
#[command(version, about)]
struct Args {
    /// Directory to write `filter.bin` and `manifest.json` into.
    #[arg(long, default_value = "dist")]
    out_dir: PathBuf,

    /// Override OSV download URL (used in tests/CI dry-runs).
    #[arg(long, default_value = OSV_NPM_ZIP_URL)]
    osv_url: String,
}

#[derive(Debug, Deserialize)]
struct Advisory {
    id: String,
    #[serde(default)]
    withdrawn: Option<String>,
    #[serde(default)]
    modified: Option<String>,
    #[serde(default)]
    affected: Vec<Affected>,
}

#[derive(Debug, Deserialize)]
struct Affected {
    package: Package,
    #[serde(default)]
    versions: Vec<String>,
    #[serde(default)]
    ranges: Vec<Range>,
}

#[derive(Debug, Deserialize)]
struct Package {
    #[serde(default)]
    name: String,
    #[serde(default)]
    ecosystem: String,
}

#[derive(Debug, Deserialize)]
struct Range {
    #[serde(default)]
    events: Vec<Event>,
}

#[derive(Debug, Deserialize, Default)]
struct Event {
    #[serde(default)]
    introduced: Option<String>,
    #[serde(default)]
    last_affected: Option<String>,
}

#[derive(Debug, Serialize)]
struct Manifest {
    format_version: u32,
    built_at_unix: u64,
    built_at_rfc3339: String,
    entry_count: u32,
    advisory_count: u32,
    bloom_m_bits: u64,
    bloom_k_hashes: u32,
    bloom_byte_len: usize,
    set_digest_sha256: String,
    filter_sha256: String,
    target_fpr: f64,
    source_url: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    newest_mal_modified: Option<String>,
}

fn main() -> Result<()> {
    let args = Args::parse();
    fs::create_dir_all(&args.out_dir)
        .with_context(|| format!("create out dir {}", args.out_dir.display()))?;

    eprintln!("downloading {}", args.osv_url);
    let zip_bytes = download(&args.osv_url)?;
    eprintln!("downloaded {} bytes", zip_bytes.len());

    let ExtractStats {
        entries,
        advisory_count,
        skipped_withdrawn,
        skipped_parse_errors,
        newest_mal_modified,
    } = extract_entries(&zip_bytes)?;
    eprintln!(
        "extracted {} unique (name, bucket) pairs from {} MAL-* advisories \
         (withdrawn skipped: {}, parse errors: {})",
        entries.len(),
        advisory_count,
        skipped_withdrawn,
        skipped_parse_errors,
    );

    if entries.len() < MIN_ENTRIES {
        bail!(
            "refusing to deploy: only {} entries (MIN_ENTRIES={}). \
             Upstream OSV format may have changed or the dump is empty.",
            entries.len(),
            MIN_ENTRIES,
        );
    }

    let set_digest = sha256_hex_of_sorted(&entries);
    let built_at = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system time before epoch")?
        .as_secs();

    let mut bloom = Bloom::new(entries.len() as u64, TARGET_FPR, default_seed());
    bloom.set_built_at(built_at);
    for (name, bucket) in &entries {
        bloom.insert(name, bucket);
    }

    let filter_bytes = bloom.encode();
    let filter_sha = sha256_hex(&filter_bytes);

    let manifest = Manifest {
        format_version: osv_bloom::FORMAT_VERSION,
        built_at_unix: built_at,
        built_at_rfc3339: format_rfc3339(built_at),
        entry_count: entries.len() as u32,
        advisory_count,
        bloom_m_bits: bloom.m(),
        bloom_k_hashes: bloom.k(),
        bloom_byte_len: filter_bytes.len(),
        set_digest_sha256: set_digest,
        filter_sha256: filter_sha,
        target_fpr: TARGET_FPR,
        source_url: args.osv_url,
        newest_mal_modified,
    };

    write_atomic(&args.out_dir.join("filter.bin"), &filter_bytes)?;
    let manifest_json = serde_json::to_vec_pretty(&manifest)?;
    write_atomic(&args.out_dir.join("manifest.json"), &manifest_json)?;
    eprintln!(
        "wrote {} ({} bytes) and manifest.json",
        args.out_dir.join("filter.bin").display(),
        filter_bytes.len(),
    );
    Ok(())
}

fn download(url: &str) -> Result<Vec<u8>> {
    let client = reqwest::blocking::Client::builder()
        .user_agent(concat!("osv-bloom-build/", env!("CARGO_PKG_VERSION")))
        .timeout(HTTP_TIMEOUT)
        .connect_timeout(std::time::Duration::from_secs(30))
        .redirect(reqwest::redirect::Policy::limited(3))
        .build()?;
    let mut resp = client.get(url).send()?.error_for_status()?;
    if let Some(len) = resp.content_length()
        && len > MAX_DOWNLOAD_BYTES
    {
        bail!(
            "OSV download advertised {len} bytes, exceeds MAX_DOWNLOAD_BYTES={MAX_DOWNLOAD_BYTES}"
        );
    }
    let cap = MAX_DOWNLOAD_BYTES.try_into().unwrap_or(usize::MAX);
    let mut buf =
        Vec::with_capacity(resp.content_length().unwrap_or(0).min(MAX_DOWNLOAD_BYTES) as usize);
    let mut reader = (&mut resp).take(MAX_DOWNLOAD_BYTES.saturating_add(1));
    std::io::copy(&mut reader, &mut buf).context("copy OSV body")?;
    if buf.len() > cap {
        bail!("OSV download exceeded MAX_DOWNLOAD_BYTES={MAX_DOWNLOAD_BYTES} mid-stream");
    }
    Ok(buf)
}

struct ExtractStats {
    entries: Vec<(String, String)>,
    advisory_count: u32,
    skipped_withdrawn: u32,
    skipped_parse_errors: u32,
    /// Max `modified` across consumed advisories. Strings compare
    /// lexicographically and RFC3339 with `Z` suffix sorts
    /// chronologically, so a plain `max()` over the strings works.
    newest_mal_modified: Option<String>,
}

/// Walks the zip, parses each `MAL-*.json` for the npm ecosystem,
/// and returns the sorted-deduped `(name, bucket)` set plus skip
/// counters. Withdrawn advisories are excluded — they no longer
/// represent malicious uploads and would only produce gratuitous
/// live-API roundtrips for consumers.
fn extract_entries(zip_bytes: &[u8]) -> Result<ExtractStats> {
    let reader = std::io::Cursor::new(zip_bytes);
    let mut archive = zip::ZipArchive::new(reader).context("open zip")?;
    let mut set: BTreeSet<(String, String)> = BTreeSet::new();
    let mut advisory_count = 0u32;
    let mut skipped_withdrawn = 0u32;
    let mut skipped_parse_errors = 0u32;
    let mut newest_mal_modified: Option<String> = None;
    // Single reusable read buffer — beats allocating a fresh String
    // per entry and avoids serde_json's slow unbuffered `from_reader`
    // path. ~200k entries × ~1-10 KB each saved adds up.
    let mut body_buf: Vec<u8> = Vec::with_capacity(16 * 1024);

    for i in 0..archive.len() {
        let mut entry = archive.by_index(i).context("read zip entry")?;
        let name = entry.name().to_string();
        if !is_mal_json(&name) {
            continue;
        }
        if entry.size() > MAX_ENTRY_BYTES {
            eprintln!(
                "warn: skipping {name}: declared size {} exceeds MAX_ENTRY_BYTES={MAX_ENTRY_BYTES}",
                entry.size()
            );
            skipped_parse_errors += 1;
            continue;
        }
        body_buf.clear();
        let mut capped = (&mut entry).take(MAX_ENTRY_BYTES);
        if let Err(e) = std::io::copy(&mut capped, &mut body_buf) {
            eprintln!("warn: skipping {name}: read error: {e}");
            skipped_parse_errors += 1;
            continue;
        }
        let adv: Advisory = match serde_json::from_slice(&body_buf) {
            Ok(a) => a,
            Err(e) => {
                eprintln!("warn: skipping {name}: parse error: {e}");
                skipped_parse_errors += 1;
                continue;
            }
        };
        if !adv.id.starts_with("MAL-") {
            continue;
        }
        if adv.withdrawn.is_some() {
            skipped_withdrawn += 1;
            continue;
        }
        advisory_count += 1;
        if let Some(modified) = adv.modified.as_deref()
            && is_rfc3339_z(modified)
        {
            // Compare on the canonical 19-char prefix only.
            // OSV mixes `2024-01-01T00:00:00Z` and `2024-01-01T00:00:00.123Z`
            // in the same dump; raw lex-compare picks the wrong winner
            // when both fall in the same second because `'Z' (0x5A) >
            // '.' (0x2E)`. Truncating to second precision sidesteps
            // the issue at the cost of sub-second resolution that we
            // don't need for "newest advisory" reporting.
            let cmp_new = &modified[..19];
            let is_newer = match newest_mal_modified.as_deref() {
                Some(current) => &current[..19] < cmp_new,
                None => true,
            };
            if is_newer {
                newest_mal_modified = Some(modified.to_string());
            }
        }
        for affected in &adv.affected {
            if !affected.package.ecosystem.eq_ignore_ascii_case("npm") {
                continue;
            }
            let pkg = affected.package.name.trim();
            if pkg.is_empty() {
                continue;
            }
            for b in buckets_for(affected) {
                set.insert((pkg.to_string(), b));
            }
        }
    }
    Ok(ExtractStats {
        entries: set.into_iter().collect(),
        advisory_count,
        skipped_withdrawn,
        skipped_parse_errors,
        newest_mal_modified,
    })
}

/// Cheap structural check that the string looks like RFC3339 UTC with
/// a trailing `Z` and the canonical `YYYY-MM-DDTHH:MM:SS` prefix.
/// Doesn't validate calendar correctness — we just need
/// "compares chronologically by `<`" to hold for a max reduction.
/// Permits an optional fractional-seconds tail (OSV uses both).
fn is_rfc3339_z(s: &str) -> bool {
    let b = s.as_bytes();
    if b.len() < 20 || !s.ends_with('Z') {
        return false;
    }
    b[4] == b'-'
        && b[7] == b'-'
        && b[10] == b'T'
        && b[13] == b':'
        && b[16] == b':'
        && b[..4].iter().all(u8::is_ascii_digit)
        && b[5..7].iter().all(u8::is_ascii_digit)
        && b[8..10].iter().all(u8::is_ascii_digit)
        && b[11..13].iter().all(u8::is_ascii_digit)
        && b[14..16].iter().all(u8::is_ascii_digit)
        && b[17..19].iter().all(u8::is_ascii_digit)
}

fn is_mal_json(entry_name: &str) -> bool {
    let leaf = entry_name.rsplit('/').next().unwrap_or(entry_name);
    leaf.starts_with("MAL-") && leaf.ends_with(".json")
}

/// Enumerate semver buckets implied by an `affected` block. Prefers
/// the explicit `versions[]` (typical for MAL-*, which usually lists
/// the exact malicious upload). Falls back to range `events[]` —
/// `introduced: "0"` becomes a wildcard since we don't enumerate the
/// npm registry to expand it.
fn buckets_for(affected: &Affected) -> Vec<String> {
    let mut out: BTreeSet<String> = BTreeSet::new();
    for v in &affected.versions {
        if let Some(b) = bucket_of(v) {
            out.insert(b);
        }
    }
    if out.is_empty() {
        for range in &affected.ranges {
            for event in &range.events {
                if let Some(introduced) = event.introduced.as_deref() {
                    if introduced == "0" {
                        out.insert(WILDCARD_BUCKET.to_string());
                    } else if let Some(b) = bucket_of(introduced) {
                        out.insert(b);
                    }
                }
                // Intentionally NOT emitting a bucket for `fixed`:
                // `fixed` is the FIRST UNAFFECTED version, so for a
                // cross-major range (introduced: "1.0.0",
                // fixed: "2.0.0") inserting bucket "2" would produce
                // a false-positive hit on a clean release. The
                // `introduced` event covers the affected major.
                if let Some(last) = event.last_affected.as_deref()
                    && let Some(b) = bucket_of(last)
                {
                    out.insert(b);
                }
            }
        }
    }
    if out.is_empty() {
        // No version info at all — emit wildcard so any version of
        // this package trips the bloom and escalates to the live API.
        out.insert(WILDCARD_BUCKET.to_string());
    }
    out.into_iter().collect()
}

/// Parse a version string leniently and return its bucket.
///
/// `semver::Version::parse` is strict-semver only: it rejects leading
/// `v`, two-component versions like `"1.0"`, four-component versions
/// like `"1.0.0.1"`, and other npm-flavoured deviations. Since OSV
/// advisories occasionally contain such strings, we try a few
/// normalisations before giving up: strip a leading `v`/`V`, pad to
/// three components, and finally fall back to parsing just the
/// leading `<major>[.<minor>]` numeric run.
fn bucket_of(version_str: &str) -> Option<String> {
    let trimmed = version_str.trim();
    if trimmed.is_empty() {
        return None;
    }
    let stripped = trimmed
        .strip_prefix('v')
        .or_else(|| trimmed.strip_prefix('V'))
        .unwrap_or(trimmed);

    if let Ok(v) = semver::Version::parse(stripped) {
        return Some(bucket(v.major, v.minor));
    }

    let dot_count = stripped.bytes().filter(|&b| b == b'.').count();
    if dot_count < 2 {
        let padded = match dot_count {
            0 => format!("{stripped}.0.0"),
            1 => format!("{stripped}.0"),
            _ => unreachable!(),
        };
        if let Ok(v) = semver::Version::parse(&padded) {
            return Some(bucket(v.major, v.minor));
        }
    }

    let head: String = stripped
        .chars()
        .take_while(|c| c.is_ascii_digit() || *c == '.')
        .collect();
    if head.is_empty() {
        return None;
    }
    let mut parts = head.split('.');
    let major: u64 = parts.next()?.parse().ok()?;
    let minor: u64 = parts.next().and_then(|s| s.parse().ok()).unwrap_or(0);
    Some(bucket(major, minor))
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(bytes);
    hex_encode(&h.finalize())
}

fn sha256_hex_of_sorted(entries: &[(String, String)]) -> String {
    let mut h = Sha256::new();
    for (name, bucket) in entries {
        h.update(name.as_bytes());
        h.update(b"\0");
        h.update(bucket.as_bytes());
        h.update(b"\n");
    }
    hex_encode(&h.finalize())
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}

fn write_atomic(path: &std::path::Path, bytes: &[u8]) -> Result<()> {
    let parent = path.parent().ok_or_else(|| anyhow!("path has no parent"))?;
    let tmp = parent.join(format!(
        ".{}.tmp",
        path.file_name().and_then(|s| s.to_str()).unwrap_or("out")
    ));
    {
        let mut f = fs::File::create(&tmp)?;
        f.write_all(bytes)?;
        f.sync_all()?;
    }
    fs::rename(&tmp, path)?;
    Ok(())
}

/// Minimal RFC 3339 formatter (UTC), no external time crate needed.
fn format_rfc3339(unix_seconds: u64) -> String {
    let (y, mo, d, h, mi, s) = unix_to_ymdhms(unix_seconds);
    format!("{y:04}-{mo:02}-{d:02}T{h:02}:{mi:02}:{s:02}Z")
}

fn unix_to_ymdhms(mut secs: u64) -> (i64, u32, u32, u32, u32, u32) {
    let s = (secs % 60) as u32;
    secs /= 60;
    let mi = (secs % 60) as u32;
    secs /= 60;
    let h = (secs % 24) as u32;
    let mut days = (secs / 24) as i64;
    let mut year: i64 = 1970;
    loop {
        let dy = if is_leap(year) { 366 } else { 365 };
        if days < dy {
            break;
        }
        days -= dy;
        year += 1;
    }
    let dim = [
        31,
        if is_leap(year) { 29 } else { 28 },
        31,
        30,
        31,
        30,
        31,
        31,
        30,
        31,
        30,
        31,
    ];
    let mut month = 1u32;
    for &md in &dim {
        if days < md as i64 {
            break;
        }
        days -= md as i64;
        month += 1;
    }
    (year, month, days as u32 + 1, h, mi, s)
}

fn is_leap(y: i64) -> bool {
    (y % 4 == 0 && y % 100 != 0) || y % 400 == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Test helper — build an `Affected` block with sensible defaults.
    /// Collapses six identical 5-line struct literals into one-liners.
    fn affected(name: &str, versions: &[&str], ranges: Vec<Range>) -> Affected {
        Affected {
            package: Package {
                name: name.into(),
                ecosystem: "npm".into(),
            },
            versions: versions.iter().map(|s| (*s).into()).collect(),
            ranges,
        }
    }

    #[test]
    fn is_mal_json_recognizes_root_and_nested() {
        assert!(is_mal_json("MAL-2024-1234.json"));
        assert!(is_mal_json("npm/MAL-2024-1234.json"));
        assert!(!is_mal_json("GHSA-aaaa-bbbb-cccc.json"));
        assert!(!is_mal_json("MAL-2024-1234.json.bak"));
    }

    #[test]
    fn bucket_of_one_x_yields_major_string() {
        assert_eq!(bucket_of("1.2.3").as_deref(), Some("1"));
        assert_eq!(bucket_of("0.3.7").as_deref(), Some("0.3"));
        assert_eq!(bucket_of("0.0.1").as_deref(), Some("0.0"));
        assert_eq!(bucket_of("not-a-version"), None);
    }

    #[test]
    fn buckets_for_uses_versions_when_present() {
        let aff = affected("evil", &["1.2.3", "2.0.0", "0.3.1"], vec![]);
        let mut got = buckets_for(&aff);
        got.sort();
        assert_eq!(got, vec!["0.3", "1", "2"]);
    }

    #[test]
    fn buckets_for_falls_back_to_range_events() {
        let aff = affected(
            "evil",
            &[],
            vec![Range {
                events: vec![Event {
                    introduced: Some("1.4.0".into()),
                    ..Default::default()
                }],
            }],
        );
        assert_eq!(buckets_for(&aff), vec!["1"]);
    }

    #[test]
    fn buckets_for_emits_wildcard_for_introduced_zero() {
        let aff = affected(
            "evil",
            &[],
            vec![Range {
                events: vec![Event {
                    introduced: Some("0".into()),
                    ..Default::default()
                }],
            }],
        );
        assert_eq!(buckets_for(&aff), vec!["*"]);
    }

    #[test]
    fn buckets_for_empty_affected_emits_wildcard() {
        let aff = affected("evil", &[], vec![]);
        assert_eq!(buckets_for(&aff), vec!["*"]);
    }

    #[test]
    fn format_rfc3339_known_timestamp() {
        // 2024-01-01T00:00:00Z
        assert_eq!(format_rfc3339(1_704_067_200), "2024-01-01T00:00:00Z");
        // 2024-02-29T12:34:56Z (leap day)
        assert_eq!(format_rfc3339(1_709_210_096), "2024-02-29T12:34:56Z");
    }

    #[test]
    fn format_rfc3339_epoch_and_non_leap_century() {
        assert_eq!(format_rfc3339(0), "1970-01-01T00:00:00Z");
        // 2100-03-01T00:00:00Z — 2100 is divisible by 100 but not 400,
        // so March 1 is *not* preceded by a Feb 29. Days since epoch
        // = 130*365 + 32 leap days + 31 (Jan) + 28 (Feb) = 47541.
        assert_eq!(format_rfc3339(4_107_542_400), "2100-03-01T00:00:00Z");
    }

    #[test]
    fn bucket_of_strips_v_prefix() {
        assert_eq!(bucket_of("v1.2.3").as_deref(), Some("1"));
        assert_eq!(bucket_of("V0.3.0").as_deref(), Some("0.3"));
    }

    #[test]
    fn bucket_of_pads_short_forms() {
        assert_eq!(bucket_of("1").as_deref(), Some("1"));
        assert_eq!(bucket_of("1.2").as_deref(), Some("1"));
        assert_eq!(bucket_of("0.3").as_deref(), Some("0.3"));
    }

    #[test]
    fn bucket_of_handles_four_component() {
        assert_eq!(bucket_of("1.2.3.4").as_deref(), Some("1"));
    }

    #[test]
    fn bucket_of_rejects_non_numeric() {
        assert_eq!(bucket_of("not-a-version"), None);
        assert_eq!(bucket_of(""), None);
        assert_eq!(bucket_of("   "), None);
    }

    #[test]
    fn bucket_of_accepts_prerelease() {
        // Strict semver accepts prerelease; major bucket unchanged.
        assert_eq!(bucket_of("1.0.0-beta.1").as_deref(), Some("1"));
        assert_eq!(bucket_of("v2.0.0-rc.1").as_deref(), Some("2"));
    }

    #[test]
    fn buckets_for_cross_major_range_no_longer_emits_fixed_major() {
        // introduced: 1.0.0, fixed: 2.0.0 → 1.x is affected, 2.0 is the
        // first clean release. `fixed` is not deserialised, so bucket
        // "2" must NOT appear.
        let aff = affected(
            "evil",
            &[],
            vec![Range {
                events: vec![Event {
                    introduced: Some("1.0.0".into()),
                    ..Default::default()
                }],
            }],
        );
        assert_eq!(buckets_for(&aff), vec!["1"]);
    }

    #[test]
    fn buckets_for_scoped_pre_one_pkg_uses_zero_minor() {
        // Regression for the TanStack 2026-05-11 incident pattern: a
        // scoped pre-1.0 package gets a `0.<minor>` bucket so the
        // reader can probe by (name, "0.x") without expanding into
        // every patch version.
        let aff = affected("@tanstack/start-client-core", &["0.18.4", "0.18.5"], vec![]);
        assert_eq!(buckets_for(&aff), vec!["0.18"]);
    }

    #[test]
    fn rfc3339_prefix_compare_handles_mixed_fractional() {
        // Regression: canonical `Z` (0x5A) lex-compares > `.` (0x2E),
        // so a naive max() over raw strings picks `"...00Z"` over a
        // chronologically later `"...00.999Z"` in the same second.
        // The build code takes `&s[..19]` to dodge this.
        let canonical = "2024-01-01T00:00:00Z";
        let fractional = "2024-01-01T00:00:00.999999Z";
        assert!(canonical > fractional, "raw lex compare is footgunny");
        assert_eq!(&canonical[..19], &fractional[..19]);
    }

    #[test]
    fn rfc3339_z_check_accepts_canonical_and_fractional() {
        assert!(is_rfc3339_z("2024-01-15T12:30:45Z"));
        assert!(is_rfc3339_z("2024-01-15T12:30:45.123Z"));
        assert!(is_rfc3339_z("2024-01-15T12:30:45.123456789Z"));
        assert!(!is_rfc3339_z("2024-01-15T12:30:45"));
        assert!(!is_rfc3339_z("not-a-date"));
        assert!(!is_rfc3339_z(""));
        assert!(!is_rfc3339_z("2024/01/15T12:30:45Z"));
    }

    #[test]
    fn buckets_for_last_affected_still_emits() {
        let aff = affected(
            "evil",
            &[],
            vec![Range {
                events: vec![
                    Event {
                        introduced: Some("1.0.0".into()),
                        ..Default::default()
                    },
                    Event {
                        last_affected: Some("3.2.1".into()),
                        ..Default::default()
                    },
                ],
            }],
        );
        let mut got = buckets_for(&aff);
        got.sort();
        assert_eq!(got, vec!["1", "3"]);
    }
}
