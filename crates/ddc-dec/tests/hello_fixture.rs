//! End-to-end fixture: a real d8-built DEX → Java source.

use ddc_dex::DexFile;
use ddc_dec::{top_level_classes, ClassOptions, DexPool};

fn pool() -> std::sync::Arc<DexPool> {
    let bytes = std::fs::read("tests/fixtures/hello.dex").unwrap();
    let mut pool = DexPool::new();
    pool.add_dex(DexFile::parse(bytes).unwrap());
    std::sync::Arc::new(pool)
}

#[test]
fn decompiles_greeter() {
    let pool = pool();
    let greeter = pool.get("Greeter").expect("Greeter class");
    let out = ddc_dec::classdec::decompile_class(&pool, greeter, &ClassOptions::default(), &std::sync::Mutex::new(Vec::new())).map_err(|e| anyhow::anyhow!("{:#}", e)).unwrap();
    assert!(out.contains("class Greeter {"), "header missing:\n{}", out);
    assert!(out.contains("private final java.lang.String name;"), "field missing:\n{}", out);
    // Provenance header: tool + version + origin image. The fixture pool
    // uses the default "dex 0" label; NO timestamp — outputs stay
    // byte-stable across runs for diffing.
    assert!(
        out.starts_with("// Decompiled by https://github.com/ejfkdev/ddc "),
        "tool header missing:\n{}",
        out
    );
    assert!(out.contains("// From: dex 0 (DEX "), "From header missing:\n{}", out);
    // The StringBuilder concat folds to the source expression.
    assert!(out.contains("return \"hi \" + this.name;"), "concat not folded:\n{}", out);
    assert!(!out.contains("StringBuilder"), "builder leaked:\n{}", out);
}

#[test]
fn decompiles_hello_main() {
    let pool = pool();
    let hello = pool.get("Hello").expect("Hello class");
    let out = ddc_dec::classdec::decompile_class(&pool, hello, &ClassOptions::default(), &std::sync::Mutex::new(Vec::new())).map_err(|e| anyhow::anyhow!("{:#}", e)).unwrap();
    // Constructor folding + call nesting across d8's temp registers.
    assert!(
        out.contains("System.out.println(new Greeter(\"world\").greet());"),
        "main not decompiled cleanly:\n{}",
        out
    );
    assert!(out.contains("counter = counter + 1;"), "static field update missing:\n{}", out);
}

#[test]
fn top_level_enumeration() {
    let pool = pool();
    let names = top_level_classes(&pool);
    assert_eq!(names, vec!["Greeter".to_string(), "Hello".to_string()]);
}
