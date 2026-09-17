//! Differential test: the boundary-walker's opcode size table must agree
//! with `decode_one` (via decode_all) on every instruction of the real
//! d8-built fixtures, and the walker must visit the same instruction pcs.

use ddc_dex::DexFile;

fn fixtures() -> Vec<std::path::PathBuf> {
    vec![
        "../ddc-dec/tests/fixtures/hello.dex".into(),
        "../ddc-dec/tests/fixtures/lambda_indy.dex".into(),
    ]
}

#[test]
fn opcode_size_table_matches_decode_one() {
    for f in fixtures() {
        let bytes = std::fs::read(&f).unwrap();
        let dex = DexFile::parse(bytes).unwrap();
        for cd in &dex.class_defs {
            let data = dex.class_data(cd);
            for m in data
                .direct_methods
                .iter()
                .chain(data.virtual_methods.iter())
            {
                if m.code_off == 0 {
                    continue;
                }
                let Some(code) = dex.code_at(m.code_off) else {
                    continue;
                };
                for insn in &code.insns {
                    let table = ddc_dex::insn::opcode_units(insn.op);
                    assert_eq!(
                        table, insn.size,
                        "{:?} method {:x}: opcode 0x{:02x} table={} decode_one={}",
                        f, m.code_off, insn.op, table, insn.size
                    );
                }
                // Walker visits exactly the same pcs in the same order.
                let expected: Vec<u32> = code.insns.iter().map(|i| i.pc).collect();
                let mut seen = Vec::new();
                let raw = dex.code_insns_bytes_at(m.code_off).unwrap();
                ddc_dex::insn::scan_instructions(raw, &mut |_op, pc, _u| {
                    seen.push(pc as u32);
                });
                assert_eq!(
                    seen, expected,
                    "{:?} method {:x}: walker pcs diverged",
                    f, m.code_off
                );
            }
        }
    }
}
