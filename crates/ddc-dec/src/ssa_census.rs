//! SSA Phase 0 census — `docs/ssa-constraint-typing.md` §3.
//!
//! Builds the per-method value graph (def values, move-copied ids, phi
//! joins at merge blocks), attaches the EXACT type facts the instruction
//! stream guarantees (const shapes, new/checkcast types, invoke/field
//! descriptors), propagates facts through phis, and counts the sites the
//! constraint solver will later address:
//!
//! - `phi-hard`: a merge whose accumulated facts hold an incompatible
//!   pair (reference vs primitive, or clashing primitive categories —
//!   the ui0/d1 `Integer` vs `int[]` family and the int↔bool family).
//! - `phi-wide`: a merge whose reference facts are mutually
//!   non-subtypes (join is legitimately Object-wide; renders today as
//!   one var typed for one path only).
//! - `recv-div` / `recv-prim`: invokes or field accesses whose receiver
//!   fact is incompatible with (or primitive against) the descriptor
//!   owner — the weibo `dq` family.
//! - `arg-div`: call/put arguments whose fact is incompatible with the
//!   formal/field type.
//!
//! READ-ONLY instrumentation: gated on `DDC_SSA_REPORT`, never touches
//! lift/render state, output is identical with the env unset.
//!
//! Phase-0 approximations (documented undercounts):
//! - handler-entry blocks start UNDEF (no try-entry state approximation);
//! - `const 0` carries no fact (flows legitimately as null/int/false);
//! - move-wide upper slots keep their previous id (the narrow/wide form
//!   is not distinguishable from `Move` alone) — stale-pair facts can
//!   add a small overcount to phi merges;
//! - AGet element facts only for primitive element chars.

use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicU64, Ordering::Relaxed};
use std::sync::{Arc, OnceLock};

use ddc_dex::insn::{InsnKind, InvokeKind};
use jdc_core::types::JavaType;

use crate::cfg::DexCfg;
use crate::lift::MethodEnv;

static ENABLED: OnceLock<bool> = OnceLock::new();

pub fn enabled() -> bool {
    *ENABLED.get_or_init(|| std::env::var_os("DDC_SSA_REPORT").is_some())
}

static METHODS: AtomicU64 = AtomicU64::new(0);
static VALUES: AtomicU64 = AtomicU64::new(0);
static PHIS: AtomicU64 = AtomicU64::new(0);
static PHI_HARD: AtomicU64 = AtomicU64::new(0);
static PHI_WIDE: AtomicU64 = AtomicU64::new(0);
static PHI_ZI: AtomicU64 = AtomicU64::new(0);
static RECV_DIV: AtomicU64 = AtomicU64::new(0);
static RECV_PRIM: AtomicU64 = AtomicU64::new(0);
static ARG_DIV: AtomicU64 = AtomicU64::new(0);

/// One-line aggregate; printed by the CLI at end of run when enabled.
pub fn report() -> String {
    format!(
        "DDC_SSA: methods={} values={} phis={} phi-hard={} phi-wide={} phi-zi={} recv-div={} recv-prim={} arg-div={}",
        METHODS.load(Relaxed),
        VALUES.load(Relaxed),
        PHIS.load(Relaxed),
        PHI_HARD.load(Relaxed),
        PHI_WIDE.load(Relaxed),
        PHI_ZI.load(Relaxed),
        RECV_DIV.load(Relaxed),
        RECV_PRIM.load(Relaxed),
        ARG_DIV.load(Relaxed),
    )
}

#[derive(Clone, PartialEq, Eq, Hash)]
enum Fact {
    Prim(char),
    /// Internal name (`java/lang/String`) or array descriptor (`[I`,
    /// `[Ljava/lang/String;`) — the forms `DexPool::is_subtype` takes.
    Ref(Arc<str>),
}

fn norm_ref(desc: &str) -> Arc<str> {
    if desc.len() > 1 && desc.starts_with('L') && desc.ends_with(';') {
        Arc::from(&desc[1..desc.len() - 1])
    } else {
        Arc::from(desc)
    }
}

fn fact_of_java(t: &JavaType) -> Option<Fact> {
    Some(match t {
        JavaType::Boolean => Fact::Prim('Z'),
        JavaType::Byte => Fact::Prim('B'),
        JavaType::Char => Fact::Prim('C'),
        JavaType::Short => Fact::Prim('S'),
        JavaType::Int => Fact::Prim('I'),
        JavaType::Float => Fact::Prim('F'),
        JavaType::Long => Fact::Prim('J'),
        JavaType::Double => Fact::Prim('D'),
        JavaType::Object(n) => Fact::Ref(n.clone()),
        JavaType::Array(_) => Fact::Ref(Arc::from(t.to_descriptor())),
        JavaType::Void => return None,
    })
}

fn wide_fact(f: &Option<Fact>) -> bool {
    matches!(f, Some(Fact::Prim('J' | 'D')))
}

/// B/S/C/I interconvert in the verifier; Z, J, F, D are distinct
/// categories for conflation purposes.
fn prim_class(c: char) -> char {
    match c {
        'B' | 'S' | 'C' => 'I',
        other => other,
    }
}

#[derive(Clone)]
enum Val {
    Undef,
    Plain { fact: Option<Fact> },
    Phi { inputs: Vec<u32> },
}

struct CallSite {
    recv: u32,
    owner: Arc<str>,
    args: Vec<(u32, JavaType)>,
}

struct FieldSite {
    /// 0 for sget/sput (no receiver).
    obj: u32,
    owner: Arc<str>,
    /// iput/sput value vid + declared type (iget/sget: None).
    val: Option<(u32, JavaType)>,
}

pub fn census_method(cfg: &DexCfg, env: &MethodEnv) {
    let nslots = env.code.registers_size as usize;
    let n = cfg.blocks.len();
    if nslots == 0 || n == 0 {
        return;
    }

    let mut vals: Vec<Val> = vec![Val::Undef];
    // (pc, slot) → def value id (stable across worklist reprocessing —
    // the fact is a pure function of the instruction).
    let mut def_vid: HashMap<(u32, u16), u32> = HashMap::default();
    // Merge-block phi ids: [block][slot], 0 = not yet minted.
    let mut phi_vid: Vec<Vec<u32>> = vec![Vec::new(); n];

    // Entry parameter facts.
    let mut params: Vec<u32> = vec![0; nslots];
    {
        let extra = if env.is_static { 0 } else { 1 };
        let pslots = env.desc.arg_slots() + extra;
        if pslots <= nslots {
            let first = nslots - pslots;
            let mut r = first;
            if !env.is_static {
                let f = Fact::Ref(norm_ref(&env.class_name));
                vals.push(Val::Plain { fact: Some(f) });
                params[r] = (vals.len() - 1) as u32;
                r += 1;
            }
            for a in &env.desc.args {
                if r >= nslots {
                    break;
                }
                vals.push(Val::Plain {
                    fact: fact_of_java(a),
                });
                params[r] = (vals.len() - 1) as u32;
                r += a.slot_size();
            }
        }
    }

    let mut out_st: Vec<Vec<u32>> = vec![vec![0; nslots]; n];
    let mut calls: Vec<CallSite> = Vec::new();
    let mut fields: Vec<FieldSite> = Vec::new();

    let mut work: VecDeque<usize> = (0..n).collect();
    let mut in_work: Vec<bool> = vec![true; n];
    let pops_cap = 8 * n + 64;
    let mut pops = 0;

    while let Some(bi) = work.pop_front() {
        pops += 1;
        if pops > pops_cap {
            break;
        }
        in_work[bi] = false;
        let b = &cfg.blocks[bi];

        // ---- in-state ----
        let mut cur: Vec<u32> = if b.pred.is_empty() {
            if bi == cfg.entry {
                params.clone()
            } else {
                vec![0; nslots]
            }
        } else if b.pred.len() == 1 && b.pred[0] != bi {
            out_st[b.pred[0]].clone()
        } else {
            // merge (or self-loop): phi per slot over live pred outs
            if phi_vid[bi].is_empty() {
                phi_vid[bi] = vec![0; nslots];
            }
            let mut v = vec![0; nslots];
            for slot in 0..nslots {
                let mut inputs: Vec<u32> = Vec::new();
                for p in &b.pred {
                    let id = out_st[*p][slot];
                    if id != 0 && !inputs.contains(&id) {
                        inputs.push(id);
                    }
                }
                if bi == cfg.entry {
                    let p = params[slot];
                    if p != 0 && !inputs.contains(&p) {
                        inputs.push(p);
                    }
                }
                if !inputs.is_empty() {
                    let pid = if phi_vid[bi][slot] != 0 {
                        phi_vid[bi][slot]
                    } else {
                        vals.push(Val::Phi { inputs: Vec::new() });
                        let id = (vals.len() - 1) as u32;
                        phi_vid[bi][slot] = id;
                        id
                    };
                    vals[pid as usize] = Val::Phi { inputs };
                    v[slot] = pid;
                }
            }
            v
        };

        // ---- walk instructions ----
        let mut last_ret: Option<Fact> = None;
        let mut last_ret_wide = false;
        for ins in &cfg.insns[b.ins_lo..b.ins_hi] {
            let k = &ins.kind;
            // (dst slot, fact, wide) for def instructions
            let mut def: Option<(u16, Option<Fact>, bool)> = None;
            match k {
                InsnKind::Move { dst, src } => {
                    let s = cur[*src as usize];
                    cur[*dst as usize] = s;
                    // move-result must immediately follow its invoke
                    last_ret = None;
                    continue;
                }
                InsnKind::MoveResult { dst } => {
                    def = Some((*dst, last_ret.clone(), last_ret_wide));
                }
                InsnKind::MoveException { dst } => {
                    def = Some((
                        *dst,
                        Some(Fact::Ref(Arc::from("java/lang/Throwable"))),
                        false,
                    ));
                }
                InsnKind::Const { dst, val, wide } => {
                    // const 0/1 legitimately flow as null/int/float/
                    // false/true (the verifier's ambiguous literals —
                    // float 0.0/1.0 share the bit pattern)
                    let f = if *val == 0 || *val == 1 {
                        None
                    } else {
                        Some(Fact::Prim(if *wide { 'J' } else { 'I' }))
                    };
                    def = Some((*dst, f, *wide));
                }
                InsnKind::ConstClass { dst, .. } => {
                    def = Some((*dst, Some(Fact::Ref(Arc::from("java/lang/Class"))), false));
                }
                InsnKind::ConstString { dst, .. } => {
                    def = Some((*dst, Some(Fact::Ref(Arc::from("java/lang/String"))), false));
                }
                InsnKind::ConstMethodHandle { dst, .. } => {
                    def = Some((
                        *dst,
                        Some(Fact::Ref(Arc::from("java/lang/invoke/MethodHandle"))),
                        false,
                    ));
                }
                InsnKind::ConstMethodType { dst, .. } => {
                    def = Some((
                        *dst,
                        Some(Fact::Ref(Arc::from("java/lang/invoke/MethodType"))),
                        false,
                    ));
                }
                InsnKind::NewInstance { dst, type_idx } => {
                    let f = Fact::Ref(norm_ref(&env.type_name_arc(*type_idx)));
                    def = Some((*dst, Some(f), false));
                }
                InsnKind::NewArray { dst, type_idx, .. } => {
                    let f = Fact::Ref(norm_ref(&env.type_name_arc(*type_idx)));
                    def = Some((*dst, Some(f), false));
                }
                InsnKind::CheckCast { reg, type_idx } => {
                    let f = Fact::Ref(norm_ref(&env.type_name_arc(*type_idx)));
                    def = Some((*reg, Some(f), false));
                }
                InsnKind::InstanceOf { dst, .. } => {
                    def = Some((*dst, Some(Fact::Prim('Z')), false));
                }
                InsnKind::ArrayLength { dst, .. } => {
                    def = Some((*dst, Some(Fact::Prim('I')), false));
                }
                InsnKind::IGet {
                    dst,
                    obj,
                    field_idx,
                } => {
                    let (owner, _, ty) = env.field_ref(*field_idx);
                    let f = fact_of_java(&ty);
                    fields.push(FieldSite {
                        obj: cur[*obj as usize],
                        owner,
                        val: None,
                    });
                    def = Some((*dst, f.clone(), wide_fact(&f)));
                }
                InsnKind::SGet { dst, field_idx } => {
                    let (_, _, ty) = env.field_ref(*field_idx);
                    let f = fact_of_java(&ty);
                    def = Some((*dst, f.clone(), wide_fact(&f)));
                }
                InsnKind::IPut {
                    value,
                    obj,
                    field_idx,
                } => {
                    let (owner, _, ty) = env.field_ref(*field_idx);
                    fields.push(FieldSite {
                        obj: cur[*obj as usize],
                        owner,
                        val: Some((cur[*value as usize], ty)),
                    });
                }
                InsnKind::SPut { value, field_idx } => {
                    let (owner, _, ty) = env.field_ref(*field_idx);
                    fields.push(FieldSite {
                        obj: 0,
                        owner,
                        val: Some((cur[*value as usize], ty)),
                    });
                }
                InsnKind::AGet { dst, ty, .. } => {
                    let f = if "IJFDZBSC".contains(*ty) {
                        Some(Fact::Prim(*ty))
                    } else {
                        None
                    };
                    def = Some((*dst, f.clone(), wide_fact(&f)));
                }
                InsnKind::Cmp { dst, .. } => {
                    def = Some((*dst, Some(Fact::Prim('I')), false));
                }
                InsnKind::Bin { dst, ty, .. } => {
                    def = Some((*dst, Some(Fact::Prim(*ty)), *ty == 'J' || *ty == 'D'));
                }
                InsnKind::BinLit { dst, .. } => {
                    def = Some((*dst, Some(Fact::Prim('I')), false));
                }
                InsnKind::Un { dst, to, .. } => {
                    def = Some((*dst, Some(Fact::Prim(*to)), *to == 'J' || *to == 'D'));
                }
                InsnKind::Invoke {
                    kind,
                    regs,
                    method_idx,
                } => {
                    let (owner, _name, desc) = env.method_ref(*method_idx);
                    last_ret = if desc.ret != JavaType::Void {
                        fact_of_java(&desc.ret)
                    } else {
                        None
                    };
                    last_ret_wide = wide_fact(&last_ret);
                    let has_recv = !matches!(kind, InvokeKind::Static);
                    let mut cursor = 0usize;
                    let recv = if has_recv && !regs.is_empty() {
                        cursor = 1;
                        cur[regs[0] as usize]
                    } else {
                        0
                    };
                    let mut args: Vec<(u32, JavaType)> = Vec::new();
                    for a in &desc.args {
                        if cursor >= regs.len() {
                            break;
                        }
                        args.push((cur[regs[cursor] as usize], a.clone()));
                        cursor += a.slot_size();
                    }
                    calls.push(CallSite { recv, owner, args });
                    continue; // last_ret must survive to the MoveResult
                }
                _ => {}
            }
            // any non-invoke instruction invalidates a pending move-result
            last_ret = None;
            last_ret_wide = false;
            if let Some((dst, f, wide)) = def {
                let key = (ins.pc, dst);
                let id = match def_vid.get(&key) {
                    Some(&id) => id,
                    None => {
                        vals.push(Val::Plain { fact: f.clone() });
                        let id = (vals.len() - 1) as u32;
                        def_vid.insert(key, id);
                        id
                    }
                };
                cur[dst as usize] = id;
                if wide || wide_fact(&f) {
                    let up = dst as usize + 1;
                    if up < nslots {
                        cur[up] = 0;
                    }
                }
            }
        }

        if out_st[bi] != cur {
            out_st[bi] = cur;
            for s in &b.succ {
                if !in_work[*s] {
                    in_work[*s] = true;
                    work.push_back(*s);
                }
            }
        }
    }

    // ---- fact accumulation over phis (rounds; sets only grow) ----
    let mut acc: Vec<Vec<Fact>> = vec![Vec::new(); vals.len()];
    for (id, v) in vals.iter().enumerate() {
        if let Val::Plain { fact: Some(f) } = v {
            acc[id].push(f.clone());
        }
    }
    for _round in 0..64 {
        let mut changed = false;
        for id in 0..vals.len() {
            let inputs = match &vals[id] {
                Val::Phi { inputs } => inputs.clone(),
                _ => continue,
            };
            let mut set = std::mem::take(&mut acc[id]);
            for inp in inputs {
                for f in &acc[inp as usize] {
                    if set.len() < 16 && !set.contains(f) {
                        set.push(f.clone());
                        changed = true;
                    }
                }
            }
            acc[id] = set;
        }
        if !changed {
            break;
        }
    }

    // ---- counting ----
    let pool = env.pool;
    // 0 compatible, 1 hard conflict, 2 wide (Object-only) join,
    // 3 Z↔I (the int/bool family — booleanize territory, reported apart)
    let cmp = |a: &Fact, b: &Fact| -> u8 {
        match (a, b) {
            (Fact::Prim(x), Fact::Prim(y)) => {
                if prim_class(*x) == prim_class(*y) {
                    0
                } else if (*x == 'Z' && prim_class(*y) == 'I')
                    || (*y == 'Z' && prim_class(*x) == 'I')
                {
                    3
                } else {
                    1
                }
            }
            (Fact::Prim(_), Fact::Ref(_)) | (Fact::Ref(_), Fact::Prim(_)) => 1,
            (Fact::Ref(x), Fact::Ref(y)) => {
                if x == y || pool.is_subtype(x, y) || pool.is_subtype(y, x) {
                    0
                } else {
                    2
                }
            }
        }
    };

    for bv in &phi_vid {
        for &id in bv.iter() {
            if id == 0 {
                continue;
            }
            let set = &acc[id as usize];
            if set.len() < 2 {
                continue;
            }
            let mut hard = false;
            let mut wide = false;
            let mut zi = false;
            for i in 0..set.len() {
                for j in i + 1..set.len() {
                    match cmp(&set[i], &set[j]) {
                        1 => hard = true,
                        2 => wide = true,
                        3 => zi = true,
                        _ => {}
                    }
                }
            }
            if hard {
                PHI_HARD.fetch_add(1, Relaxed);
            } else if wide {
                PHI_WIDE.fetch_add(1, Relaxed);
            } else if zi {
                PHI_ZI.fetch_add(1, Relaxed);
            }
        }
    }

    // receiver/object vs declared owner; value/arg vs declared type
    fn owner_check(vid: u32, owner: &str, acc: &[Vec<Fact>], pool: &crate::DexPool) {
        if vid == 0 {
            return;
        }
        let mut prim = false;
        let mut diverge = false;
        for f in &acc[vid as usize] {
            match f {
                Fact::Prim(_) => prim = true,
                Fact::Ref(r) => {
                    if !pool.is_subtype(r, owner) && !pool.is_subtype(owner, r) {
                        diverge = true;
                    }
                }
            }
        }
        if prim {
            RECV_PRIM.fetch_add(1, Relaxed);
        }
        if diverge {
            RECV_DIV.fetch_add(1, Relaxed);
        }
    }

    for c in &calls {
        owner_check(c.recv, &c.owner, &acc, pool);
        for (vid, formal) in &c.args {
            if *vid == 0 {
                continue;
            }
            let Some(ff) = fact_of_java(formal) else {
                continue;
            };
            if acc[*vid as usize]
                .iter()
                .any(|f| matches!(cmp(f, &ff), 1 | 2))
            {
                ARG_DIV.fetch_add(1, Relaxed);
            }
        }
    }
    for fsite in &fields {
        owner_check(fsite.obj, &fsite.owner, &acc, pool);
        if let Some((vid, ty)) = &fsite.val {
            if *vid == 0 {
                continue;
            }
            let Some(ff) = fact_of_java(ty) else {
                continue;
            };
            if acc[*vid as usize]
                .iter()
                .any(|f| matches!(cmp(f, &ff), 1 | 2))
            {
                ARG_DIV.fetch_add(1, Relaxed);
            }
        }
    }

    let phis = phi_vid
        .iter()
        .flat_map(|v| v.iter())
        .filter(|&&x| x != 0)
        .count() as u64;
    PHIS.fetch_add(phis, Relaxed);
    VALUES.fetch_add(vals.len() as u64, Relaxed);
    METHODS.fetch_add(1, Relaxed);
}
