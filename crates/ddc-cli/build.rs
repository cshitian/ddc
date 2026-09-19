//! Compress the plaintext platform-symbol table into the build output.
//! The repo keeps a readable, diffable `src/platform_symbols.txt`; the
//! binary embeds the raw-DEFLATE blob from OUT_DIR (the runtime
//! inflater is raw, not zlib-wrapped — same contract as the generator).

fn main() {
    println!("cargo:rerun-if-changed=src/platform_symbols.txt");
    let src = std::fs::read("src/platform_symbols.txt").expect("platform_symbols.txt");
    let mut enc = flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::best());
    use std::io::Write;
    enc.write_all(&src).unwrap();
    let gz = enc.finish().unwrap();
    let out = std::env::var("OUT_DIR").unwrap();
    std::fs::write(
        std::path::Path::new(&out).join("platform_symbols.txt.gz"),
        gz,
    )
    .expect("write compressed symbols");
}
