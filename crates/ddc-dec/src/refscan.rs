//! LOCAL-OK reference scan for the field-obscuring nested-type renames
//! (round-59 Design B).
//!
//! A field-clash rename (nested type whose simple name equals an
//! enclosing-class field, JLS 6.4.2 obscuring) is only safe to apply when
//! EVERY class referencing the nested type lives inside the root family —
//! the top-level class whose file renders it plus all `root$*` descendants.
//! The rename then perturbs exactly one rendered file: the symbol table
//! outside the family is unchanged, so javac's error-recovery behavior on
//! other files cannot flip. Design A (ungated global rename) proved why
//! the gate matters: on weibo — 11218 pre-existing class/package name
//! conflicts — even perfectly-covered renames flipped ambiguous
//! type-vs-package resolutions corpus-wide, turning "missing supertype,
//! body attribution suppressed" files into full Object cascades
//! (+36916 errors). reqable/lark improved (−1653/−5221), so the rule is
//! right; only its blast radius needed bounding.
//!
//! The scan covers, per DEX image: super/interfaces, field & method
//! signatures, instruction operands (type@/field@/method@/call-site@/
//! method-handle@/method-type@), the full annotations directory (class,
//! field, method, parameter sets, with recursive encoded-value walks) and
//! class static values. Catch-handler type lists are NOT scanned (a
//! foreign class catching a field-clash candidate as a Throwable is
//! vanishingly rare; a miss leaks one rename, not the Design-A storm).

use std::sync::Arc;

use ddc_dex::annotations::{read_encoded_annotation, EncodedValue};
use ddc_dex::DexFile;
use jdc_core::FxHashMap as HashMap;
use jdc_core::FxHashSet as HashSet;

const NONE: u32 = u32::MAX;

/// One rename candidate: internal name → root (top-level) internal name.
/// Returns the subset whose every referrer is inside the root's family.
pub fn local_ok(dexes: &[Arc<DexFile>], cands: &HashMap<String, String>) -> HashSet<String> {
    if cands.is_empty() {
        return HashSet::default();
    }
    // Deterministic slot order (map iteration is not).
    let mut names: Vec<&String> = cands.keys().collect();
    names.sort();
    let slots: Vec<(&str, &str, String, String)> = names
        .iter()
        .map(|n| {
            let root = cands.get(*n).map(|s| s.as_str()).unwrap_or(*n);
            (
                n.as_str(),
                root,
                format!("{root}$"),
                format!("L{n};"),
            )
        })
        .collect();
    // Primary descriptor per candidate PLUS its shadow-package twin.
    // The twin (`L{R}/{t};` for nested `R$t`) matters when the root
    // doubles as a package (weibo's obfuscator ships 11218 such
    // class/package conflicts): the dotted path `pkg.R.t` that foreign
    // files use for the PACKAGE class only resolved through class R's
    // member type `t` while that member existed — renaming the member
    // breaks the accidental resolution ("找不到符号 类 t 位置: 类 R",
    // the SGChatFragment pattern behind Design-B's weibo residual). An
    // external reference to the twin therefore kills the candidate
    // exactly like one to the primary. Primaries contain `$`, twins
    // never do, so the key spaces are disjoint.
    let desc_owned: Vec<(String, u32)> = slots
        .iter()
        .enumerate()
        .flat_map(|(i, s)| {
            let mut v = vec![(s.3.clone(), i as u32)];
            let twin = format!("L{};", s.0.replace('$', "/"));
            if twin != s.3 {
                v.push((twin, i as u32));
            }
            v
        })
        .collect();
    let desc_slot: HashMap<&str, u32> = desc_owned
        .iter()
        .map(|(d, i)| (d.as_str(), *i))
        .collect();

    // Images are scanned on a small thread pool (cap 4: the per-image
    // sentinel tables cost a few MB each, and the full-decompile workers
    // — the memory-hungry phase — start right after this).
    let mut merged: Vec<bool> = vec![false; slots.len()];
    let nthreads = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1)
        .min(4)
        .min(dexes.len().max(1));
    let chunk = dexes.len().div_ceil(nthreads).max(1);
    std::thread::scope(|scope| {
        let handles: Vec<_> = dexes
            .chunks(chunk)
            .map(|group| {
                let slots = &slots;
                let desc_slot = &desc_slot;
                scope.spawn(move || {
                    let mut dead: Vec<bool> = vec![false; slots.len()];
                    for dex in group {
                        let d = scan_image(dex, slots, desc_slot);
                        for (i, x) in d.into_iter().enumerate() {
                            dead[i] |= x;
                        }
                        if dead.iter().all(|&x| x) {
                            break; // every candidate already proven external
                        }
                    }
                    dead
                })
            })
            .collect();
        for h in handles {
            if let Ok(dead) = h.join() {
                for (i, d) in dead.into_iter().enumerate() {
                    merged[i] |= d;
                }
            } else {
                // A panicked scan means unknown referrers: treat every
                // candidate as external (no renames) rather than risk a
                // Design-A perturbation.
                for d in merged.iter_mut() {
                    *d = true;
                }
            }
        }
    });

    slots
        .iter()
        .zip(merged.iter())
        .filter(|(_, dead)| !*dead)
        .map(|(s, _)| s.0.to_string())
        .collect()
}

type SlotInfo<'a> = (&'a str, &'a str, String, String);

fn scan_image(
    dex: &DexFile,
    slots: &[SlotInfo],
    desc_slot: &HashMap<&str, u32>,
) -> Vec<bool> {
    let mut dead: Vec<bool> = vec![false; slots.len()];
    // type_idx → slot for this image's type table.
    let mut cand_type: Vec<u32> = vec![NONE; dex.type_count()];
    for (idx, slot) in cand_type.iter_mut().enumerate() {
        if let Some(&s) = desc_slot.get(dex.type_name(idx as u32)) {
            *slot = s;
        }
    }
    // field_idx → (class-slot, type-slot): a field reference touches the
    // declaring class AND the field's type.
    let mut field_a: Vec<u32> = vec![NONE; dex.field_count()];
    let mut field_b: Vec<u32> = vec![NONE; dex.field_count()];
    for idx in 0..dex.field_count() {
        let f = dex.field(idx as u32);
        field_a[idx] = cand_type.get(f.class_idx as usize).copied().unwrap_or(NONE);
        field_b[idx] = cand_type.get(f.type_idx as usize).copied().unwrap_or(NONE);
    }
    // method_idx → slots (class, proto return, proto params). First hit
    // inline, the (rare) rest in a side map.
    let mut meth_a: Vec<u32> = vec![NONE; dex.method_count()];
    let mut meth_extra: HashMap<u32, Vec<u32>> = HashMap::default();
    for idx in 0..dex.method_count() {
        let m = dex.method(idx as u32);
        let mut hits: Vec<u32> = Vec::new();
        let mut push = |s: u32, hits: &mut Vec<u32>| {
            if s != NONE && !hits.contains(&s) {
                hits.push(s);
            }
        };
        push(cand_type.get(m.class_idx as usize).copied().unwrap_or(NONE), &mut hits);
        let proto = dex.proto(m.proto_idx);
        push(
            cand_type.get(proto.return_type_idx as usize).copied().unwrap_or(NONE),
            &mut hits,
        );
        for &t in dex.proto_params(m.proto_idx) {
            push(cand_type.get(t as usize).copied().unwrap_or(NONE), &mut hits);
        }
        if !hits.is_empty() {
            meth_a[idx] = hits[0];
            if hits.len() > 1 {
                meth_extra.insert(idx as u32, hits.split_off(1));
            }
        }
    }

    // Proto idx → slots (for invoke-polymorphic / const-method-type /
    // call sites).
    let proto_slots = |pidx: u32, out: &mut Vec<u32>| {
        let proto = dex.proto(pidx);
        let mut push = |s: u32| {
            if s != NONE && !out.contains(&s) {
                out.push(s);
            }
        };
        push(cand_type.get(proto.return_type_idx as usize).copied().unwrap_or(NONE));
        for &t in dex.proto_params(pidx) {
            push(cand_type.get(t as usize).copied().unwrap_or(NONE));
        }
    };

    let raw = dex.raw();
    let mut record = |slot: u32, referrer: &str, dead: &mut Vec<bool>| {
        if slot == NONE || dead[slot as usize] {
            return;
        }
        let (_, root, prefix, _) = &slots[slot as usize];
        if referrer != *root && !referrer.starts_with(prefix.as_str()) {
            dead[slot as usize] = true;
        }
    };
    let record_field = |fidx: u32, referrer: &str, dead: &mut Vec<bool>| {
        if let Some(&a) = field_a.get(fidx as usize) {
            record(a, referrer, dead);
        }
        if let Some(&b) = field_b.get(fidx as usize) {
            record(b, referrer, dead);
        }
    };
    let record_meth = |midx: u32, referrer: &str, dead: &mut Vec<bool>| {
        if let Some(&a) = meth_a.get(midx as usize) {
            record(a, referrer, dead);
        }
        if let Some(extra) = meth_extra.get(&midx) {
            for &s in extra {
                record(s, referrer, dead);
            }
        }
    };
    // Encoded-value walk: annotation elements, static values, call-site
    // linker args. Local stack — hits are rare, the allocation is not on
    // any hot path, and it keeps every scanner closure `Fn` (shared
    // captures only) so they compose without borrow conflicts.
    let record_ev = |ev: &EncodedValue, referrer: &str, dead: &mut Vec<bool>| {
        let mut stack: Vec<EncodedValue> = vec![ev.clone()];
        while let Some(v) = stack.pop() {
            match v {
                EncodedValue::Type(t) => {
                    let s = cand_type.get(t as usize).copied().unwrap_or(NONE);
                    record(s, referrer, dead);
                }
                EncodedValue::Field(f) | EncodedValue::Enum(f) => {
                    record_field(f, referrer, dead);
                }
                EncodedValue::Method(m) => record_meth(m, referrer, dead),
                EncodedValue::MethodType(p) => {
                    let mut out = Vec::new();
                    proto_slots(p, &mut out);
                    for s in out {
                        record(s, referrer, dead);
                    }
                }
                EncodedValue::MethodHandle(h) => {
                    if let Some(mh) = dex.method_handle(h) {
                        if mh.is_field {
                            record_field(mh.target_id, referrer, dead);
                        } else {
                            record_meth(mh.target_id, referrer, dead);
                        }
                    }
                }
                EncodedValue::Array(items) => stack.extend(items),
                EncodedValue::Annotation(a) => {
                    let s = cand_type.get(a.type_idx as usize).copied().unwrap_or(NONE);
                    record(s, referrer, dead);
                    stack.extend(a.elements.into_iter().map(|(_, v)| v));
                }
                _ => {}
            }
        }
    };

    let u4 = |off: usize| -> u32 {
        raw.get(off..off + 4)
            .map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
            .unwrap_or(0)
    };
    // One annotation_set_item: size + item offsets; each item is
    // visibility(u8) + encoded_annotation.
    let walk_set = |set_off: u32, referrer: &str, dead: &mut Vec<bool>| {
        let set = set_off as usize;
        if set == 0 || set + 4 > raw.len() {
            return;
        }
        let n = u4(set) as usize;
        for i in 0..n {
            let item = u4(set + 4 + 4 * i) as usize;
            if item == 0 || item + 1 >= raw.len() {
                continue;
            }
            if let Some((a, _)) = read_encoded_annotation(raw, item + 1) {
                let s = cand_type.get(a.type_idx as usize).copied().unwrap_or(NONE);
                record(s, referrer, dead);
                for (_, v) in a.elements {
                    record_ev(&v, referrer, dead);
                }
            }
        }
    };
    // annotations_directory_item: class set + [idx,set] triples for
    // fields, methods, parameter lists.
    let walk_ann_dir = |dir_off: u32, referrer: &str, dead: &mut Vec<bool>| {
        let off = dir_off as usize;
        if off == 0 || off + 16 > raw.len() {
            return;
        }
        walk_set(u4(off), referrer, dead);
        let mut p = off + 16;
        for k in 0..3 {
            let n = u4(off + 4 + 4 * k) as usize;
            for _ in 0..n {
                if p + 8 > raw.len() {
                    return;
                }
                walk_set(u4(p + 4), referrer, dead);
                p += 8;
            }
        }
    };

    for cd in &dex.class_defs {
        if dead.iter().all(|&d| d) {
            break; // every candidate already proven external
        }
        let referrer = dex.class_name(cd.class_idx);
        // Super + interfaces.
        let s = cand_type.get(cd.superclass_idx as usize).copied().unwrap_or(NONE);
        record(s, &referrer, &mut dead);
        for i in dex.interfaces_of(cd) {
            let s = cand_type.get(i as usize).copied().unwrap_or(NONE);
            record(s, &referrer, &mut dead);
        }
        // Signatures + code.
        let data = dex.class_data(cd);
        for f in data.static_fields.iter().chain(data.instance_fields.iter()) {
            record_field(f.field_idx, &referrer, &mut dead);
        }
        for m in data.direct_methods.iter().chain(data.virtual_methods.iter()) {
            record_meth(m.method_idx, &referrer, &mut dead);
            let Some(code) = (m.code_off != 0).then(|| dex.code_insns_bytes_at(m.code_off)).flatten() else {
                continue;
            };
            ddc_dex::insn::scan_instructions(code, &mut |op, pc, bytes| {
                let unit = |i: usize| -> u32 {
                    bytes
                        .get(2 * i..2 * i + 2)
                        .map(|b| u16::from_le_bytes([b[0], b[1]]) as u32)
                        .unwrap_or(NONE)
                };
                match op {
                    // const-class, check-cast, instanceof, new-instance,
                    // new-array, filled-new-array(/range),
                    // const-method-type — type@ at unit pc+1.
                    0x1c | 0x1f | 0x20 | 0x22..=0x25 | 0xff => {
                        let t = unit(pc + 1);
                        let s = cand_type.get(t as usize).copied().unwrap_or(NONE);
                        record(s, &referrer, &mut dead);
                    }
                    // Field accesses — field@ at unit pc+1.
                    0x52..=0x6d => record_field(unit(pc + 1), &referrer, &mut dead),
                    // Invokes — method@ at unit pc+1.
                    0x6e..=0x72 | 0x74..=0x78 => record_meth(unit(pc + 1), &referrer, &mut dead),
                    // invoke-polymorphic(/range): method@ pc+1, proto@ pc+2.
                    0xfa | 0xfb => {
                        record_meth(unit(pc + 1), &referrer, &mut dead);
                        let mut out = Vec::new();
                        proto_slots(unit(pc + 2), &mut out);
                        for s in out {
                            record(s, &referrer, &mut dead);
                        }
                    }
                    // invoke-custom: call-site@ pc+1.
                    0xfc => {
                        if let Some(cs) = dex.call_site(unit(pc + 1)) {
                            let mut out = Vec::new();
                            proto_slots(cs.proto_idx, &mut out);
                            for s in out {
                                record(s, &referrer, &mut dead);
                            }
                            for v in &cs.linker_args {
                                record_ev(v, &referrer, &mut dead);
                            }
                        }
                    }
                    // const-method-handle: handle@ pc+1.
                    0xfe => {
                        if let Some(mh) = dex.method_handle(unit(pc + 1)) {
                            if mh.is_field {
                                record_field(mh.target_id, &referrer, &mut dead);
                            } else {
                                record_meth(mh.target_id, &referrer, &mut dead);
                            }
                        }
                    }
                    _ => {}
                }
            });
        }
        // Annotations directory + static values.
        walk_ann_dir(cd.annotations_off, &referrer, &mut dead);
        if cd.static_values_off != 0 {
            for v in dex.static_values(cd.static_values_off) {
                record_ev(&v, &referrer, &mut dead);
            }
        }
    }
    dead
}
