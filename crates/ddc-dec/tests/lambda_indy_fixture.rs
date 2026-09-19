//! Native invoke-custom (DEX 039, `--no-desugaring`): call sites, method
//! handles, lambdas and StringConcatFactory folding.

use ddc_dec::{ClassOptions, DexPool};
use ddc_dex::DexFile;

fn pool() -> std::sync::Arc<DexPool> {
    let bytes = std::fs::read("tests/fixtures/lambda_indy.dex").unwrap();
    let mut pool = DexPool::new();
    pool.add_dex(DexFile::parse(bytes).unwrap());
    std::sync::Arc::new(pool)
}

#[test]
fn version_and_call_sites() {
    let bytes = std::fs::read("tests/fixtures/lambda_indy.dex").unwrap();
    let dex = DexFile::parse(bytes).unwrap();
    assert_eq!(dex.version, "039");
    assert!(dex.call_site_count() >= 5, "call sites missing");
    assert!(dex.method_handle_count() >= 5, "method handles missing");
    // A LambdaMetafactory site with its impl method.
    let any_meta = (0..dex.call_site_count() as u32).any(|i| {
        let cs = dex.call_site(i).unwrap();
        cs.linker_args
            .iter()
            .any(|v| matches!(v, ddc_dex::annotations::EncodedValue::MethodHandle(_)))
    });
    assert!(any_meta, "no lambda site");
}

#[test]
fn lambda_and_methodref_render() {
    let pool = pool();
    let lt = pool.get("LambdaTest").expect("LambdaTest");
    let out = ddc_dec::classdec::decompile_class(
        &pool,
        lt,
        &ClassOptions::default(),
        &std::sync::Mutex::new(Vec::new()),
    )
    .map_err(|e| anyhow::anyhow!("{:#}", e))
    .unwrap();
    // Method reference: Comparator.comparing(String::length).
    assert!(
        out.contains("java.lang.String::length"),
        "method ref missing:\n{}",
        out
    );
    // Lambda with the instantiated SAM arity.
    assert!(
        out.contains("(a0) -> LambdaTest.lambda$run$0(a0)"),
        "lambda missing:\n{}",
        out
    );
    // StringConcatFactory folded into `+` (the String param carries its
    // jadx-style name from apply_local_names).
    assert!(
        out.contains("\"hi \" + str"),
        "concat not folded:\n{}",
        out
    );
    // The impl bodies stay correct (Integer param → num).
    assert!(
        out.contains("num.intValue() * 2 + 1"),
        "impl body wrong:\n{}",
        out
    );
}
