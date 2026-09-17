//! Subcommand integration tests: the progressive-analysis fast paths
//! (manifest/info/listclasses/getclass/findrefs), run against the built
//! binary. The AXML fixture is a real AndroidManifest.xml pulled from an
//! APK; the dex fixture is the shared d8-built hello.dex.

use std::path::PathBuf;
use std::process::{Command, Output};

fn ddc() -> Command {
    let mut c = Command::new(env!("CARGO_BIN_EXE_ddc"));
    c.env_remove("DDC_NOWRITE").env_remove("DDC_CLASSTIME");
    c
}

fn fixture() -> PathBuf {
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.push("../ddc-dec/tests/fixtures/hello.dex");
    p
}

fn axml_fixture() -> PathBuf {
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.push("tests/fixtures/AndroidManifest.bin.xml");
    p
}

fn tmp(name: &str) -> PathBuf {
    let mut p = std::env::temp_dir();
    p.push(format!("ddc-sub-test-{name}"));
    let _ = std::fs::remove_dir_all(&p);
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

#[test]
fn manifest_decodes_real_axml() {
    let o = run(ddc().arg("manifest").arg(axml_fixture()));
    assert!(o.status.success(), "{}", stderr(&o));
    let xml = stdout(&o);
    assert!(xml.contains("<manifest"), "root missing:\n{}", xml);
    assert!(xml.contains("package=\"com.reqable.android\""), "package:\n{}", xml);
    assert!(xml.contains("uses-permission"), "permissions:\n{}", xml);
    assert!(xml.contains("<application"), "application:\n{}", xml);
    // Elements are balanced: every close matches an open.
    let opens = xml.matches('<').count();
    assert!(opens > 20, "suspiciously small manifest:\n{}", xml);
}

#[test]
fn listclasses_filters() {
    let o = run(ddc().arg("listclasses").arg(fixture()));
    assert!(o.status.success(), "{}", stderr(&o));
    let all = stdout(&o);
    assert!(all.contains("Hello\n"));
    assert!(all.contains("Greeter\n"));

    let o = run(ddc().arg("listclasses").arg(fixture()).arg("gre"));
    assert!(o.status.success());
    let filtered = stdout(&o);
    assert!(filtered.contains("Greeter"));
    assert!(!filtered.contains("Hello\n"), "filter did not apply:\n{}", filtered);
    assert!(stderr(&o).contains("1 of 2 classes"), "{}", stderr(&o));
}

#[test]
fn info_reports_tables() {
    let o = run(ddc().arg("info").arg(fixture()));
    assert!(o.status.success(), "{}", stderr(&o));
    let out = stdout(&o);
    assert!(out.contains("classes"), "{}", out);
    assert!(out.contains("methods"), "{}", out);
    assert!(out.contains("total: 1 image(s)"), "{}", out);
}

#[test]
fn getclass_prints_one_class() {
    let o = run(ddc().arg("getclass").arg(fixture()).arg("Greeter"));
    assert!(o.status.success(), "{}", stderr(&o));
    let out = stdout(&o);
    assert!(out.contains("class Greeter {"));
    assert!(!out.contains("class Hello"), "other class leaked:\n{}", out);

    // -o writes the file instead.
    let f = tmp("gc").join("G.java");
    let o = run(ddc().arg("getclass").arg(fixture()).arg("Greeter").arg("-o").arg(&f));
    assert!(o.status.success(), "{}", stderr(&o));
    assert!(std::fs::read_to_string(&f).unwrap().contains("class Greeter {"));
    std::fs::remove_dir_all(tmp("gc"));
}

#[test]
fn getclass_unknown_class_errors() {
    let o = run(ddc().arg("getclass").arg(fixture()).arg("no.Such"));
    assert_eq!(o.status.code(), Some(2));
    assert!(stderr(&o).contains("not found"));
}

#[test]
fn findrefs_all_four_kinds() {
    // string
    let o = run(ddc().arg("findrefs").arg(fixture()).arg("string").arg("hi"));
    assert!(o.status.success(), "{}", stderr(&o));
    let out = stdout(&o);
    assert!(out.contains("Greeter.greet()"), "{}", out);
    assert!(out.contains("const-string \"hi \""), "{}", out);

    // method
    let o = run(ddc().arg("findrefs").arg(fixture()).arg("method").arg("greet"));
    assert!(o.status.success());
    let out = stdout(&o);
    assert!(out.contains("Hello.main("), "{}", out);
    assert!(out.contains("invoke Greeter->greet()"), "{}", out);

    // field
    let o = run(ddc().arg("findrefs").arg(fixture()).arg("field").arg("counter"));
    assert!(o.status.success());
    let out = stdout(&o);
    assert!(out.contains("sget Hello->counter:I"), "{}", out);
    assert!(out.contains("sput Hello->counter:I"), "{}", out);

    // type (any naming form normalizes)
    let o = run(ddc().arg("findrefs").arg(fixture()).arg("type").arg("Greeter"));
    assert!(o.status.success());
    let out = stdout(&o);
    assert!(out.contains("new-instance LGreeter;"), "{}", out);
}

#[test]
fn findrefs_with_class_filter() {
    // Exact class filter: name greet exists on Greeter only.
    let o = run(
        ddc().arg("findrefs")
            .arg(fixture())
            .arg("method")
            .arg("greet")
            .arg("--class")
            .arg("Greeter"),
    );
    assert!(o.status.success(), "{}", stderr(&o));
    assert!(stdout(&o).contains("invoke Greeter->greet()"));

    // Wrong class: no method ids resolve → no hits.
    let o = run(
        ddc().arg("findrefs")
            .arg(fixture())
            .arg("method")
            .arg("greet")
            .arg("--class")
            .arg("Nope"),
    );
    assert!(o.status.success());
    assert!(stderr(&o).contains("0 hit(s)"), "{}", stderr(&o));
}

#[test]
fn findrefs_bad_invocation() {
    let o = run(ddc().arg("findrefs").arg(fixture()).arg("bogus").arg("x"));
    assert_eq!(o.status.code(), Some(2));
    assert!(stderr(&o).contains("unknown kind"));

    let o = run(ddc().arg("findrefs").arg(fixture()));
    assert_eq!(o.status.code(), Some(2));
    assert!(stderr(&o).contains("findrefs needs:"));
}
