//! Manifest facts and resource-side helpers shared by the browse
//! subcommands: raw extraction of AndroidManifest.xml from an APK (or a
//! nested XAPK/APKS container), plus line-level parsing of the generated
//! XML for package / launcher / component facts.

use anyhow::Result;
use std::path::Path;

use crate::{inflate, zip_entries, ZipMethod};

/// The manifest's raw bytes plus a label naming where they came from
/// (`AndroidManifest.xml`, or `base.apk!AndroidManifest.xml` in a
/// container). mmap'd: only the manifest entry's range is ever touched.
pub(crate) fn manifest_bytes(input: &Path) -> Result<(String, Vec<u8>)> {
    let src = crate::inputs::map_source(input)?;
    let bytes: &[u8] = src.bytes();
    if bytes.len() < 4 || &bytes[..2] != b"PK" {
        // A raw file is itself a binary XML (`.axml`).
        return Ok((
            input
                .file_name()
                .and_then(|s| s.to_str())
                .unwrap_or("input")
                .to_string(),
            bytes.to_vec(),
        ));
    }
    let entries = zip_entries(bytes)?;
    if let Some(entry) = entries.iter().find(|n| n.name == "AndroidManifest.xml") {
        let raw = entry_bytes(bytes, entry)?;
        return Ok((entry.name.clone(), raw));
    }
    // Nested container: base APK first, then name order.
    let stem = input
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("input");
    let mut apks: Vec<&crate::ZipEntry> = entries
        .iter()
        .filter(|e| e.name.ends_with(".apk"))
        .collect();
    apks.sort_by_key(|e| {
        let base = e.name == "base.apk"
            || e.name == format!("{stem}.apk")
            || e.name.starts_with("split_base");
        (!base, e.name.clone())
    });
    for apk in apks {
        let inner = entry_bytes(bytes, apk)?;
        if inner.len() < 4 || &inner[..2] != b"PK" {
            continue;
        }
        if let Some(e) = zip_entries(&inner)?
            .into_iter()
            .find(|n| n.name == "AndroidManifest.xml")
        {
            let raw = entry_bytes(&inner, &e)?;
            return Ok((format!("{}!{}", apk.name, e.name), raw));
        }
    }
    anyhow::bail!(
        "{}",
        crate::lang::bif!(
            "{0}: no AndroidManifest.xml entry (in container or its APKs)",
            "{0}：没有 AndroidManifest.xml 条目（容器及其 APK 中都没有）";
            input.display()
        )
    )
}

/// Inflate one zip entry out of an archive image.
pub(crate) fn entry_bytes(archive: &[u8], entry: &crate::ZipEntry) -> Result<Vec<u8>> {
    Ok(match entry.method {
        ZipMethod::Stored => archive[entry.range.clone()].to_vec(),
        ZipMethod::Deflate => inflate(&archive[entry.range.clone()])?,
    })
}

/// The decoded manifest XML text + its source label.
pub(crate) fn manifest_xml(input: &Path) -> Result<(String, String)> {
    let (label, raw) = manifest_bytes(input)?;
    let text = crate::axml::axml_to_xml(&raw)
        .map_err(|e| anyhow::anyhow!("{}: {}", input.display(), e))?;
    Ok((label, text))
}

/// The facts a reverse engineer needs from a manifest in one pass.
#[derive(Default)]
pub(crate) struct ManifestFacts {
    pub package: String,
    /// `android:name` of <application> when it names a custom Application.
    pub application: Option<String>,
    /// The MAIN/LAUNCHER activity (or activity-alias target).
    pub launcher: Option<String>,
}

/// Line-level walk of the generated XML. The decoder emits one element per
/// line with 4-space nesting, so "current activity + intent-filter state"
/// is a simple scan.
pub(crate) fn parse_facts(xml: &str) -> ManifestFacts {
    let mut f = ManifestFacts::default();
    let mut cur_activity: Option<String> = None;
    let mut cur_alias_target: Option<String> = None;
    let mut in_filter = false;
    let mut saw_main = false;
    let mut saw_launcher = false;
    for line in xml.lines() {
        let t = line.trim();
        let attr = |name: &str| -> Option<String> {
            // name="value" — value has no embedded quotes (the decoder
            // escapes them as &quot;).
            let pat = format!("{name}=\"");
            let start = t.find(&pat)? + pat.len();
            let end = t[start..].find('"')? + start;
            Some(t[start..end].to_string())
        };
        if t.starts_with("<manifest") {
            f.package = attr("package").unwrap_or_default();
        } else if t.starts_with("<application") && f.application.is_none() {
            f.application = attr("name");
        } else if t.starts_with("<activity") || t.starts_with("<activity-alias") {
            cur_activity = attr("name");
            cur_alias_target = if t.starts_with("<activity-alias") {
                attr("targetActivity")
            } else {
                None
            };
        } else if t.starts_with("<intent-filter") {
            in_filter = true;
            saw_main = false;
            saw_launcher = false;
        } else if t.starts_with("</intent-filter") {
            if in_filter && saw_main && saw_launcher && f.launcher.is_none() {
                let name = cur_alias_target.clone().or_else(|| cur_activity.clone());
                if let Some(n) = name {
                    f.launcher = Some(resolve_name(&f.package, &n));
                }
            }
            in_filter = false;
        } else if in_filter {
            if let Some(a) = attr("name") {
                if a == "android.intent.action.MAIN" {
                    saw_main = true;
                } else if a == "android.intent.category.LAUNCHER" {
                    saw_launcher = true;
                }
            }
        }
    }
    f
}

/// Manifest names are relative by convention: `.MainActivity` → package
/// prefix; a bare word → package + '.' + word; anything with a dot is
/// absolute (unless it starts with one).
pub(crate) fn resolve_name(package: &str, name: &str) -> String {
    if name.starts_with('.') {
        format!("{package}{name}")
    } else if name.contains('.') {
        name.to_string()
    } else {
        format!("{package}.{name}")
    }
}

/// `--component` filter for the manifest subcommand: keeps the manifest
/// header line plus every line of the requested element kind (activities,
/// services, …) at any depth, so per-component attributes survive.
pub(crate) fn component_xml(xml: &str, component: &str) -> String {
    let (singular, plural) = match component {
        "activity" | "activities" => ("activity", "activities"),
        "service" | "services" => ("service", "services"),
        "receiver" | "receivers" => ("receiver", "receivers"),
        "provider" | "providers" => ("provider", "providers"),
        "activity-alias" => ("activity-alias", "activity-aliases"),
        "application" => ("application", "application"),
        "permission" | "permissions" => ("uses-permission", "permissions"),
        "launcher" => ("launcher", "launcher"),
        _ => return xml.to_string(),
    };
    let facts = parse_facts(xml);
    let mut out = String::new();
    for line in xml.lines() {
        let t = line.trim();
        if t.starts_with("<manifest") {
            out.push_str(line);
            out.push('\n');
        } else if component == "launcher" {
            let wanted = facts.launcher.clone().unwrap_or_default();
            if !wanted.is_empty() && line.contains(&wanted) {
                out.push_str(line);
                out.push('\n');
            }
        } else if t.starts_with(&format!("<{singular}")) {
            out.push_str(line);
            out.push('\n');
        }
    }
    let _ = plural;
    out
}

/// Convenience: the manifest facts for an input (decode + parse).
pub(crate) fn facts_for(input: &Path) -> Result<ManifestFacts> {
    let (_, xml) = manifest_xml(input)?;
    Ok(parse_facts(&xml))
}
