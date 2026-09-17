//! XAPK / APKS / APKM container support: a zip of APKs (base + config
//! splits), each contributing its own classes*.dex images. The fixture is
//! built by hand as a STORED-only zip (no compressor dependency).

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

fn ddc() -> Command {
    let mut c = Command::new(env!("CARGO_BIN_EXE_ddc"));
    c.env_remove("DDC_NOWRITE").env_remove("DDC_CLASSTIME");
    c
}

fn hello_dex() -> Vec<u8> {
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.push("../ddc-dec/tests/fixtures/hello.dex");
    std::fs::read(&p).unwrap()
}

fn axml() -> Vec<u8> {
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.push("tests/fixtures/AndroidManifest.bin.xml");
    std::fs::read(&p).unwrap()
}

fn tmp(name: &str) -> PathBuf {
    let mut p = std::env::temp_dir();
    p.push(format!("ddc-xapk-test-{name}"));
    let _ = std::fs::remove_dir_all(&p);
    p
}

// ---- minimal STORED-zip writer -------------------------------------------

fn u16le(v: u16) -> [u8; 2] {
    v.to_le_bytes()
}
fn u32le(v: u32) -> [u8; 4] {
    v.to_le_bytes()
}

/// Build a stored (uncompressed) zip from (name, data) pairs.
fn stored_zip(items: &[(&str, Vec<u8>)]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut cds: Vec<(String, u32, u32, u32)> = Vec::new(); // name, crc, size, offset
    for (name, data) in items {
        let offset = out.len() as u32;
        let crc = crc32(data);
        out.extend_from_slice(&u32le(0x0403_4b50));
        out.extend_from_slice(&u16le(20)); // version
        out.extend_from_slice(&u16le(0)); // flags
        out.extend_from_slice(&u16le(0)); // method: stored
        out.extend_from_slice(&u16le(0)); // time
        out.extend_from_slice(&u16le(0)); // date
        out.extend_from_slice(&u32le(crc));
        out.extend_from_slice(&u32le(data.len() as u32));
        out.extend_from_slice(&u32le(data.len() as u32));
        out.extend_from_slice(&u16le(name.len() as u16));
        out.extend_from_slice(&u16le(0)); // extra len
        out.extend_from_slice(name.as_bytes());
        out.extend_from_slice(data);
        cds.push((name.to_string(), crc, data.len() as u32, offset));
    }
    let cd_start = out.len() as u32;
    for (name, crc, size, offset) in &cds {
        out.extend_from_slice(&u32le(0x0201_4b50));
        out.extend_from_slice(&u16le(20));
        out.extend_from_slice(&u16le(20));
        out.extend_from_slice(&u16le(0));
        out.extend_from_slice(&u16le(0));
        out.extend_from_slice(&u16le(0));
        out.extend_from_slice(&u16le(0));
        out.extend_from_slice(&u32le(*crc));
        out.extend_from_slice(&u32le(*size));
        out.extend_from_slice(&u32le(*size));
        out.extend_from_slice(&u16le(name.len() as u16));
        out.extend_from_slice(&u16le(0));
        out.extend_from_slice(&u16le(0));
        out.extend_from_slice(&u16le(0));
        out.extend_from_slice(&u16le(0));
        out.extend_from_slice(&u32le(0)); // disk
        out.extend_from_slice(&u32le(*offset));
        out.extend_from_slice(name.as_bytes());
    }
    let cd_size = out.len() as u32 - cd_start;
    out.extend_from_slice(&u32le(0x0605_4b50));
    out.extend_from_slice(&u16le(0));
    out.extend_from_slice(&u16le(0));
    out.extend_from_slice(&u16le(cds.len() as u16));
    out.extend_from_slice(&u16le(cds.len() as u16));
    out.extend_from_slice(&u32le(cd_size));
    out.extend_from_slice(&u32le(cd_start));
    out.extend_from_slice(&u16le(0));
    out
}

fn crc32(data: &[u8]) -> u32 {
    let mut crc = 0xFFFF_FFFFu32;
    for &b in data {
        crc ^= b as u32;
        for _ in 0..8 {
            if crc & 1 != 0 {
                crc = (crc >> 1) ^ 0xEDB8_8320;
            } else {
                crc >>= 1;
            }
        }
    }
    !crc
}

/// An XAPK fixture: base.apk (hello.dex + manifest) + config.arm64_v8a.apk
/// (a second copy of hello.dex — duplicate class names must resolve to the
/// BASE) + manifest.json (ignored).
fn xapk_fixture(dir: &Path) -> PathBuf {
    let dex = hello_dex();
    let manifest = axml();
    let base = stored_zip(&[
        ("AndroidManifest.xml", manifest),
        ("classes.dex", dex.clone()),
    ]);
    let config = stored_zip(&[("classes.dex", dex)]);
    let outer = stored_zip(&[
        ("manifest.json", br#"{"package_name":"com.example"}"#.to_vec()),
        ("config.arm64_v8a.apk", config),
        ("base.apk", base),
    ]);
    let p = dir.join("app.xapk");
    std::fs::write(&p, outer).unwrap();
    p
}

fn run(c: &mut Command) -> Output {
    c.output().expect("spawn ddc")
}

fn stdout(o: &Output) -> String {
    String::from_utf8_lossy(&o.stdout).into_owned()
}

fn stderr(o: &Output) -> String {
    String::from_utf8_lossy(&o.stderr).into_owned()
}

fn count_java(dir: &Path) -> usize {
    fn walk(p: &Path, n: &mut usize) {
        if let Ok(rd) = std::fs::read_dir(p) {
            for e in rd.flatten() {
                let path = e.path();
                if path.is_dir() {
                    walk(&path, n);
                } else if path.extension().and_then(|e| e.to_str()) == Some("java") {
                    *n += 1;
                }
            }
        }
    }
    let mut n = 0;
    walk(dir, &mut n);
    n
}

#[test]
fn xapk_full_pipeline() {
    let dir = tmp("xapk");
    std::fs::create_dir_all(&dir).unwrap();
    let xapk = xapk_fixture(&dir);

    // listclasses: classes from the container (base's dex; the config
    // split's duplicate classes dedup to it).
    let o = run(ddc().arg("listclasses").arg(&xapk));
    assert!(o.status.success(), "{}", stderr(&o));
    let out = stdout(&o);
    assert!(out.contains("Hello\n"));
    assert!(out.contains("Greeter\n"));

    // manifest: recursed into base.apk's AndroidManifest.xml.
    let o = run(ddc().arg("manifest").arg(&xapk));
    assert!(o.status.success(), "{}", stderr(&o));
    let out = stdout(&o);
    assert!(out.contains("<manifest"), "{}", out);
    assert!(out.contains("com.reqable.android"), "{}", out);

    // findrefs scans every inner APK's dex.
    let o = run(ddc().arg("findrefs").arg(&xapk).arg("string").arg("hi"));
    assert!(o.status.success(), "{}", stderr(&o));
    assert!(stdout(&o).contains("matched=(hi )"), "{}", stdout(&o));

    // getclass resolves through the container.
    let o = run(ddc().arg("getclass").arg(&xapk).arg("Greeter"));
    assert!(o.status.success(), "{}", stderr(&o));
    let out = stdout(&o);
    assert!(out.contains("class Greeter {"));
    // Provenance: three-segment label.
    assert!(out.contains("app!base.apk!classes.dex"), "label:\n{}", out);

    // Full decompile: positional output dir.
    let outdir = dir.join("out");
    let o = run(ddc().arg(&xapk).arg(&outdir));
    assert!(o.status.success(), "{}", stderr(&o));
    assert_eq!(count_java(&outdir), 2, "duplicate split classes must dedup");
    std::fs::remove_dir_all(&dir);
}

#[test]
fn xapk_dex_filter_targets_inner_apk() {
    let dir = tmp("xapkfilter");
    std::fs::create_dir_all(&dir).unwrap();
    let xapk = xapk_fixture(&dir);

    // `--dex base` keeps only the base APK's images.
    let o = run(ddc().arg("findrefs").arg(&xapk).arg("--dex").arg("base").arg("string").arg("hi"));
    assert!(o.status.success(), "{}", stderr(&o));
    assert!(stdout(&o).contains("matched=(hi )"));

    // `--dex config` keeps only the config split.
    let o = run(
        ddc().arg("findrefs")
            .arg(&xapk)
            .arg("--dex")
            .arg("config.arm64")
            .arg("string")
            .arg("hi"),
    );
    assert!(o.status.success(), "{}", stderr(&o));
    assert!(stdout(&o).contains("matched=(hi )"));

    // info reports both inner APKs' images.
    let o = run(ddc().arg("info").arg(&xapk));
    assert!(o.status.success(), "{}", stderr(&o));
    let out = stdout(&o);
    assert!(out.contains("base.apk"), "{}", out);
    assert!(out.contains("config.arm64_v8a.apk"), "{}", out);
    std::fs::remove_dir_all(&dir);
}
