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

use anyhow::{Context, Result, anyhow};
use clap::Parser;
use osv_bloom::{Bloom, WILDCARD_BUCKET, bucket, default_seed};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

const OSV_NPM_ZIP_URL: &str =
    "https://osv-vulnerabilities.storage.googleapis.com/npm/all.zip";

/// Target false-positive rate. With ~10k entries this lands the
/// bitset around ~18 KB; even at 100k entries (10x headroom) it's
/// ~180 KB.
const TARGET_FPR: f64 = 0.001;

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
    fixed: Option<String>,
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
}

fn main() -> Result<()> {
    let args = Args::parse();
    fs::create_dir_all(&args.out_dir)
        .with_context(|| format!("create out dir {}", args.out_dir.display()))?;

    eprintln!("downloading {}", args.osv_url);
    let zip_bytes = download(&args.osv_url)?;
    eprintln!("downloaded {} bytes", zip_bytes.len());

    let (entries, advisory_count) = extract_entries(&zip_bytes)?;
    eprintln!(
        "extracted {} unique (name, bucket) pairs from {} MAL-* advisories",
        entries.len(),
        advisory_count,
    );

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
        .build()?;
    let resp = client.get(url).send()?.error_for_status()?;
    Ok(resp.bytes()?.to_vec())
}

/// Walks the zip, parses each `MAL-*.json` for the npm ecosystem,
/// and returns the sorted-deduped `(name, bucket)` set plus the
/// advisory count consumed.
fn extract_entries(zip_bytes: &[u8]) -> Result<(Vec<(String, String)>, u32)> {
    let reader = std::io::Cursor::new(zip_bytes);
    let mut archive = zip::ZipArchive::new(reader).context("open zip")?;
    let mut set: BTreeSet<(String, String)> = BTreeSet::new();
    let mut advisory_count = 0u32;

    for i in 0..archive.len() {
        let mut entry = archive.by_index(i).context("read zip entry")?;
        let name = entry.name().to_string();
        if !is_mal_json(&name) {
            continue;
        }
        let mut body = String::new();
        entry.read_to_string(&mut body).with_context(|| format!("read {name}"))?;
        let adv: Advisory = match serde_json::from_str(&body) {
            Ok(a) => a,
            Err(e) => {
                eprintln!("warn: skipping {name}: parse error: {e}");
                continue;
            }
        };
        if !adv.id.starts_with("MAL-") {
            continue;
        }
        advisory_count += 1;
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
    Ok((set.into_iter().collect(), advisory_count))
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
                if let Some(fixed) = event.fixed.as_deref() {
                    if let Some(b) = bucket_of(fixed) {
                        // The fix lands in the next bucket but the
                        // affected set lives in the bucket BEFORE this
                        // one. For a single fixed major boundary
                        // (e.g. fixed: "2.0.0" means 1.x affected) the
                        // introduced event already covered that. We
                        // still emit the fixed major as a defensive
                        // measure for cases where introduced is "0"
                        // and we fell back to wildcard — but we
                        // already wildcarded, so this is a no-op there.
                        out.insert(b);
                    }
                }
                if let Some(last) = event.last_affected.as_deref() {
                    if let Some(b) = bucket_of(last) {
                        out.insert(b);
                    }
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

fn bucket_of(version_str: &str) -> Option<String> {
    let v = semver::Version::parse(version_str).ok()?;
    Some(bucket(v.major, v.minor))
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
    let dim = [31, if is_leap(year) { 29 } else { 28 }, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
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
        let aff = Affected {
            package: Package {
                name: "evil".into(),
                ecosystem: "npm".into(),
            },
            versions: vec!["1.2.3".into(), "2.0.0".into(), "0.3.1".into()],
            ranges: vec![],
        };
        let mut got = buckets_for(&aff);
        got.sort();
        assert_eq!(got, vec!["0.3", "1", "2"]);
    }

    #[test]
    fn buckets_for_falls_back_to_range_events() {
        let aff = Affected {
            package: Package {
                name: "evil".into(),
                ecosystem: "npm".into(),
            },
            versions: vec![],
            ranges: vec![Range {
                events: vec![
                    Event {
                        introduced: Some("1.4.0".into()),
                        ..Default::default()
                    },
                    Event {
                        fixed: Some("1.4.2".into()),
                        ..Default::default()
                    },
                ],
            }],
        };
        let got = buckets_for(&aff);
        assert_eq!(got, vec!["1"]);
    }

    #[test]
    fn buckets_for_emits_wildcard_for_introduced_zero() {
        let aff = Affected {
            package: Package {
                name: "evil".into(),
                ecosystem: "npm".into(),
            },
            versions: vec![],
            ranges: vec![Range {
                events: vec![Event {
                    introduced: Some("0".into()),
                    ..Default::default()
                }],
            }],
        };
        assert_eq!(buckets_for(&aff), vec!["*"]);
    }

    #[test]
    fn buckets_for_empty_affected_emits_wildcard() {
        let aff = Affected {
            package: Package {
                name: "evil".into(),
                ecosystem: "npm".into(),
            },
            versions: vec![],
            ranges: vec![],
        };
        assert_eq!(buckets_for(&aff), vec!["*"]);
    }

    #[test]
    fn format_rfc3339_known_timestamp() {
        // 2024-01-01T00:00:00Z
        assert_eq!(format_rfc3339(1_704_067_200), "2024-01-01T00:00:00Z");
        // 2024-02-29T12:34:56Z (leap day)
        assert_eq!(format_rfc3339(1_709_210_096), "2024-02-29T12:34:56Z");
    }

}
