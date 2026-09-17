//! Shared input plumbing for the ddc CLI: expand inputs (files/dirs) to
//! dex-bearing files, then inflate + parse every image in parallel.

use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use ddc_dex::DexFile;

use crate::{inflate, zip_entries, ZipEntry, ZipMethod};

/// A raw (possibly still deflated) DEX image with its origin label. The
/// archive bytes are SHARED (Arc) and each image is a range slice — the
/// old per-entry owned copies doubled a 353MB APK's resident footprint
/// before the first inflate.
pub struct Image {
    pub label: String,
    data: std::sync::Arc<Vec<u8>>,
    range: std::ops::Range<usize>,
    method: ZipMethod,
}

/// Expand input paths: files pass through, directories are scanned
/// recursively (sorted for determinism).
pub fn expand_inputs(inputs: &[PathBuf]) -> Result<Vec<PathBuf>> {
    let mut files: Vec<PathBuf> = Vec::new();
    for input in inputs {
        if input.is_dir() {
            let before = files.len();
            walk_dex_files(input, &mut files)
                .with_context(|| format!("scanning {}", input.display()))?;
            if files.len() == before {
                bail!("no .dex/.apk/.jar/.zip files under {}", input.display());
            }
        } else if input.is_file() {
            files.push(input.clone());
        } else {
            bail!("input not found: {}", input.display());
        }
    }
    Ok(files)
}

fn walk_dex_files(dir: &Path, out: &mut Vec<PathBuf>) -> std::io::Result<()> {
    let mut entries: Vec<_> = std::fs::read_dir(dir)?.collect::<std::io::Result<_>>()?;
    entries.sort_by_key(|e| e.file_name());
    for e in entries {
        let p = e.path();
        if p.is_dir() {
            walk_dex_files(&p, out)?;
        } else if is_dex_ext(&p) {
            out.push(p);
        }
    }
    Ok(())
}

pub fn is_dex_ext(p: &Path) -> bool {
    matches!(
        p.extension().and_then(|e| e.to_str()).map(|e| e.to_ascii_lowercase()),
        Some(ref e) if matches!(e.as_str(), "dex" | "apk" | "jar" | "zip")
    )
}

/// Whether a directory contains (recursively) anything the pool could
/// read. False → an output-directory candidate, not an input.
pub fn dir_has_dex_files(dir: &Path) -> bool {
    let mut v = Vec::new();
    walk_dex_files(dir, &mut v).is_ok() && !v.is_empty()
}

/// Collect raw dex images from every input file: zips contribute all
/// their `*.dex` entries (classes.dex, classes2.dex... numeric order
/// first), raw dex files contribute themselves. Labels read
/// `<input-stem>!<zip-entry>`.
pub fn collect_images(files: &[PathBuf]) -> Result<Vec<Image>> {
    let mut images: Vec<Image> = Vec::new();
    for f in files {
        let bytes = std::sync::Arc::new(
            std::fs::read(f).with_context(|| format!("read {}", f.display()))?,
        );
        let stem = f
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("input")
            .to_string();
        if bytes.len() >= 4 && &bytes[..2] == b"PK" {
            let entries = zip_entries(&bytes)?;
            let mut dexes: Vec<(u64, ZipEntry)> = Vec::new();
            let mut extra: Vec<ZipEntry> = Vec::new();
            for e in entries {
                if !e.name.ends_with(".dex") {
                    continue;
                }
                let core = e.name.trim_end_matches(".dex");
                if let Some(num) = core.strip_prefix("classes") {
                    let key = num.parse::<u64>().unwrap_or(0);
                    dexes.push((key, e));
                } else {
                    extra.push(e);
                }
            }
            if dexes.is_empty() && extra.is_empty() {
                bail!(
                    "{}: no *.dex entries in archive (is it an Android APK/dx jar?)",
                    f.display()
                );
            }
            dexes.sort_by_key(|(k, _)| *k);
            let mk = |e: ZipEntry| Image {
                label: format!("{}!{}", stem, e.name),
                data: bytes.clone(),
                range: e.range,
                method: e.method,
            };
            images.extend(dexes.into_iter().map(|(_, e)| mk(e)));
            images.extend(extra.into_iter().map(mk));
        } else if bytes.len() >= 4 && &bytes[..3] == b"dex" {
            let n = bytes.len();
            images.push(Image {
                label: stem,
                data: bytes,
                range: 0..n,
                method: ZipMethod::Stored,
            });
        } else {
            bail!(
                "{}: not a DEX image or ZIP/APK archive (bad magic)",
                f.display()
            );
        }
    }
    Ok(images)
}

/// Filter images by dex entry name (`--dex classes20` matches the entry
/// part of `<stem>!classes20.dex`; a bare raw dex matches its whole
/// label). Substring, case-insensitive; multiple patterns OR. Filtering
/// BEFORE the parse keeps unwanted images off the decode entirely.
pub fn filter_images_by_dex(
    images: Vec<Image>,
    patterns: &[String],
) -> Result<Vec<Image>> {
    if patterns.is_empty() {
        return Ok(images);
    }
    let entry = |label: &str| match label.rsplit_once('!') {
        Some((_, e)) => e.to_string(),
        None => label.to_string(),
    };
    let pats: Vec<String> = patterns.iter().map(|p| p.to_ascii_lowercase()).collect();
    let (kept, dropped): (Vec<Image>, Vec<Image>) = images
        .into_iter()
        .partition(|img| {
            let e = entry(&img.label).to_ascii_lowercase();
            pats.iter().any(|p| e.contains(p.as_str()))
        });
    if kept.is_empty() {
        let mut names: Vec<String> = dropped.iter().map(|img| entry(&img.label)).collect();
        names.sort();
        names.dedup();
        bail!(
            "--dex {}: no matching dex images (available: {})",
            patterns.join(", "),
            names.join(", ")
        );
    }
    Ok(kept)
}

/// Inflate AND parse each image on its own thread. Returns
/// `(label, DexFile)` pairs in input order.
pub fn parse_images(images: Vec<Image>) -> Result<Vec<(String, DexFile)>> {
    let mut handles = Vec::new();
    for img in images {
        let label = img.label.clone();
        handles.push((
            label,
            std::thread::spawn(move || {
                let raw = match img.method {
                    ZipMethod::Stored => img.data[img.range].to_vec(),
                    ZipMethod::Deflate => inflate(&img.data[img.range])
                        .map_err(|e| e.to_string())?,
                };
                DexFile::parse(raw)
                    .map_err(|e| e.to_string())
                    .map(|dex| (img.label, dex))
            }),
        ));
    }
    let mut out = Vec::with_capacity(handles.len());
    for (name, h) in handles {
        let parsed = h
            .join()
            .map_err(|_| anyhow::anyhow!("parse thread panicked: {}", name))?
            .map_err(|e| anyhow::anyhow!("parse {}: {}", name, e))?;
        out.push(parsed);
    }
    Ok(out)
}
