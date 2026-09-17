//! Dalvik instruction decoding: all formats plus payload pseudo-instructions.
//!
//! Offsets are in 16-bit code units throughout (matching DEX try tables and
//! the CFG builder). Payload bodies (`packed-switch`, `sparse-switch`,
//! `fill-array-data`) are decoded out-of-line into a side map; linear
//! decoding skips past them.

use std::collections::HashMap;

use crate::reader::Cursor;

/// Comparison ops shared by `if-*` and `cmp*`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CmpOp {
    Eq,
    Ne,
    Lt,
    Ge,
    Gt,
    Le,
}

/// Numeric operation shared by the four binop families.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArithOp {
    Add,
    Sub,
    Mul,
    Div,
    Rem,
    And,
    Or,
    Xor,
    Shl,
    Shr,
    Ushr,
}

/// `cmpl/cmpg` flavour.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CmpKind {
    CmplF,
    CmpgF,
    CmplD,
    CmpgD,
    CmpJ,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InvokeKind {
    Virtual,
    Super,
    Direct,
    Static,
    Interface,
    Polymorphic,
}

/// Fully decoded instruction semantics.
#[derive(Debug, Clone)]
pub enum InsnKind {
    Nop,
    /// Plain register move (the lifter treats wide/object as typing hints).
    Move { dst: u16, src: u16 },
    MoveResult { dst: u16 },
    MoveException { dst: u16 },
    ReturnVoid,
    Return { src: u16 },
    /// `dst = literal` with the value's natural width.
    Const { dst: u16, val: i64, wide: bool },
    /// `dst = type` class literal.
    ConstClass { dst: u16, type_idx: u32 },
    ConstString { dst: u16, str_idx: u32 },
    MonitorEnter { reg: u16 },
    MonitorExit { reg: u16 },
    /// In-place cast: the register's value becomes `Cast(type)`.
    CheckCast { reg: u16, type_idx: u32 },
    InstanceOf { dst: u16, src: u16, type_idx: u32 },
    ArrayLength { dst: u16, src: u16 },
    NewInstance { dst: u16, type_idx: u32 },
    NewArray { dst: u16, size: u16, type_idx: u32 },
    FilledNewArray { regs: Vec<u16>, type_idx: u32 },
    /// Fill the array in `reg` from the payload at `payload_pc`.
    FillArrayData { reg: u16, payload_pc: u32 },
    Throw { reg: u16 },
    /// Absolute target pc.
    Goto { target: u32 },
    PackedSwitch { reg: u16, payload_pc: u32 },
    SparseSwitch { reg: u16, payload_pc: u32 },
    Cmp { dst: u16, a: u16, b: u16, kind: CmpKind },
    /// `if-*` with `z=false` for two-register forms; `target` is absolute.
    If { op: CmpOp, a: u16, b: u16, z: bool, target: u32 },
    AGet { dst: u16, array: u16, index: u16, ty: char },
    APut { value: u16, array: u16, index: u16, ty: char },
    IGet { dst: u16, obj: u16, field_idx: u32 },
    IPut { value: u16, obj: u16, field_idx: u32 },
    SGet { dst: u16, field_idx: u32 },
    SPut { value: u16, field_idx: u32 },
    Invoke { kind: InvokeKind, regs: Vec<u16>, method_idx: u32 },
    /// `dst = op(src)` (neg / not / conversion); `from`/`to` primitive chars.
    Un { dst: u16, src: u16, op: UnArith, from: char, to: char },
    /// `dst = a op b` on primitive `ty`.
    Bin { op: ArithOp, dst: u16, a: u16, b: u16, ty: char },
    /// `dst = a op lit` (or `lit - a` for `rsub`).
    BinLit { op: ArithOp, dst: u16, a: u16, lit: i32, rsub: bool },
    /// `dst = method-handle constant` (DEX 037+).
    ConstMethodHandle { dst: u16, handle_idx: u32 },
    /// `dst = proto constant` (DEX 037+).
    ConstMethodType { dst: u16, proto_idx: u32 },
    /// invoke-custom: `regs` are the call site's dynamic arguments; BBBB is
    /// a call_site_idx (NOT a method index).
    InvokeCustom { call_site_idx: u32, regs: Vec<u16> },
    /// ODEX quickened / unassigned opcodes: cannot be lifted.
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnArith {
    Neg,
    Not,
    Conv,
}

#[derive(Debug, Clone)]
pub enum Payload {
    /// `ident 0x0100`: targets are offsets RELATIVE to the switch insn.
    Packed { first_key: i32, targets: Vec<i32> },
    /// `ident 0x0200`.
    Sparse { pairs: Vec<(i32, i32)> },
    /// `ident 0x0300`.
    ArrayData { elem_width: u16, size: u32, data: Vec<u8> },
}

/// One decoded instruction.
#[derive(Debug, Clone)]
pub struct Insn {
    /// Code-unit offset of the first unit.
    pub pc: u32,
    /// Total code units consumed (payloads excluded — they are not Insns).
    pub size: u32,
    pub op: u8,
    pub kind: InsnKind,
}

impl Insn {
    pub fn is_branch(&self) -> bool {
        matches!(
            self.kind,
            InsnKind::Goto { .. }
                | InsnKind::If { .. }
                | InsnKind::PackedSwitch { .. }
                | InsnKind::SparseSwitch { .. }
        )
    }

    pub fn is_terminator(&self) -> bool {
        matches!(self.kind, InsnKind::ReturnVoid | InsnKind::Return { .. } | InsnKind::Throw { .. })
    }
}

/// Sign-extend a 4-bit literal.
fn sign4(v: u16) -> i64 {
    let x = v as i64;
    (x << 60) >> 60
}

fn u16s(bytes: &[u8]) -> Vec<u16> {
    bytes
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .collect()
}

/// Payload size in code units (0 when malformed).
fn payload_units(bytes: &[u8], off: usize) -> usize {
    let units = u16s(bytes);
    let unit = |i: usize| -> u16 { units.get(i).copied().unwrap_or(0) };
    match unit(off) {
        0x0100 => {
            let size = unit(off + 1) as usize;
            4 + size * 2
        }
        0x0200 => {
            let size = unit(off + 1) as usize;
            2 + size * 4
        }
        0x0300 => {
            let width = unit(off + 1) as usize;
            let size = (unit(off + 2) as usize) | ((unit(off + 3) as usize) << 16);
            4 + (size * width + 1) / 2
        }
        _ => 0,
    }
}

fn parse_payload(bytes: &[u8], off: usize) -> Option<Payload> {
    let units = u16s(bytes);
    let unit = |i: usize| -> u16 { units.get(i).copied().unwrap_or(0) };
    match unit(off) {
        0x0100 => {
            let size = unit(off + 1) as usize;
            let first_key =
                (unit(off + 2) as i32) | ((unit(off + 3) as i32) << 16);
            let mut targets = Vec::with_capacity(size);
            for i in 0..size {
                let t = (unit(off + 4 + 2 * i) as i32) | ((unit(off + 5 + 2 * i) as i32) << 16);
                targets.push(t);
            }
            Some(Payload::Packed { first_key, targets })
        }
        0x0200 => {
            let size = unit(off + 1) as usize;
            let mut pairs = Vec::with_capacity(size);
            for i in 0..size {
                let k = (unit(off + 2 + 2 * i) as i32) | ((unit(off + 3 + 2 * i) as i32) << 16);
                let t = (unit(off + 2 + 2 * size + 2 * i) as i32)
                    | ((unit(off + 3 + 2 * size + 2 * i) as i32) << 16);
                pairs.push((k, t));
            }
            Some(Payload::Sparse { pairs })
        }
        0x0300 => {
            let elem_width = unit(off + 1);
            let size = (unit(off + 2) as u32) | ((unit(off + 3) as u32) << 16);
            let n = size as usize * elem_width as usize;
            let start = (off + 4) * 2;
            let data = if start + n <= bytes.len() {
                bytes[start..start + n].to_vec()
            } else {
                Vec::new()
            };
            Some(Payload::ArrayData { elem_width, size, data })
        }
        _ => None,
    }
}

/// Instruction width in code units for a format number.
fn format_units(fmt: u8) -> u32 {
    match fmt {
        10 | 12 | 11 => 1,
        20 | 22 | 21 | 23 => 2,
        30 | 31 | 32 | 35 | 3 => 3,
        45 | 4 => 4,
        51 | 5 => 5,
        _ => 1,
    }
}

/// Decode the semantics of one instruction at code-unit `pc` given the
/// full unit stream. Returns `(size, kind)`.
fn decode_one(units: &[u16], pc: usize) -> (u32, InsnKind) {
    let op = (units[pc] & 0xff) as u8;
    let aa = units[pc] >> 8; // the 8-bit A field
    let u = |i: usize| -> u16 { units.get(i).copied().unwrap_or(0) };
    let i32of = |i: usize| -> i32 {
        let lo = u(i) as u32;
        let hi = u(i + 1) as u32;
        ((lo | (hi << 16)) as u32) as i32
    };

    // 4-bit register fields of the first unit.
    let a4 = (units[pc] >> 12) & 0xf;
    let b4 = (units[pc] >> 8) & 0xf;

    let mk = match op {
        // ---- moves ----
        0x00 => {
            // nop; payload idents also land here but are handled by the
            // caller before dispatch.
            return (1, InsnKind::Nop);
        }
        0x01 | 0x04 | 0x07 => InsnKind::Move { dst: b4 as u16, src: a4 as u16 },
        0x02 | 0x05 | 0x08 => {
            return (2, InsnKind::Move { dst: aa as u16, src: u(pc + 1) });
        }
        0x03 | 0x06 | 0x09 => {
            return (
                3,
                InsnKind::Move { dst: u(pc + 1), src: u(pc + 2) },
            );
        }
        0x0a..=0x0c => InsnKind::MoveResult { dst: aa as u16 },
        0x0d => InsnKind::MoveException { dst: aa as u16 },
        0x0e => InsnKind::ReturnVoid,
        0x0f | 0x10 | 0x11 => InsnKind::Return { src: aa as u16 },

        // ---- consts ----
        0x12 => InsnKind::Const {
            dst: b4 as u16,
            val: sign4(a4),
            wide: false,
        },
        0x13 | 0x16 => {
            return (
                2,
                InsnKind::Const {
                    dst: aa as u16,
                    val: (u(pc + 1) as i16) as i64,
                    wide: op == 0x16,
                },
            );
        }
        0x14 | 0x17 => {
            return (
                3,
                InsnKind::Const {
                    dst: aa as u16,
                    val: i32of(pc + 1) as i64,
                    wide: op == 0x17,
                },
            );
        }
        0x15 => {
            return (
                2,
                InsnKind::Const {
                    dst: aa as u16,
                    val: ((u(pc + 1) as u32) << 16) as i32 as i64,
                    wide: false,
                },
            );
        }
        0x18 => {
            let lo = u64::from(i32of(pc + 1) as u32);
            let hi = u64::from(i32of(pc + 3) as u32);
            return (
                5,
                InsnKind::Const { dst: aa as u16, val: (lo | (hi << 32)) as i64, wide: true },
            );
        }
        0x19 => {
            return (
                2,
                InsnKind::Const {
                    dst: aa as u16,
                    val: ((u(pc + 1) as u64) << 48) as i64,
                    wide: true,
                },
            );
        }
        0x1a | 0x1b => {
            let idx = if op == 0x1b {
                (u(pc + 1) as u32) | ((u(pc + 2) as u32) << 16)
            } else {
                u(pc + 1) as u32
            };
            return (
                if op == 0x1b { 3 } else { 2 },
                InsnKind::ConstString { dst: aa as u16, str_idx: idx },
            );
        }
        0x1c => {
            return (
                2,
                InsnKind::ConstClass { dst: aa as u16, type_idx: u(pc + 1) as u32 },
            );
        }

        // ---- monitors / casts / arrays ----
        0x1d => InsnKind::MonitorEnter { reg: aa as u16 },
        0x1e => InsnKind::MonitorExit { reg: aa as u16 },
        0x1f => {
            return (
                2,
                InsnKind::CheckCast { reg: aa as u16, type_idx: u(pc + 1) as u32 },
            );
        }
        0x20 => {
            return (
                2,
                InsnKind::InstanceOf {
                    dst: b4 as u16,
                    src: a4 as u16,
                    type_idx: u(pc + 1) as u32,
                },
            );
        }
        0x21 => InsnKind::ArrayLength { dst: b4 as u16, src: a4 as u16 },
        0x22 => {
            return (
                2,
                InsnKind::NewInstance { dst: aa as u16, type_idx: u(pc + 1) as u32 },
            );
        }
        0x23 => {
            return (
                2,
                InsnKind::NewArray {
                    dst: b4 as u16,
                    size: a4 as u16,
                    type_idx: u(pc + 1) as u32,
                },
            );
        }
        0x24 | 0x25 => {
            // filled-new-array: 35c / 3rc
            let (regs, idx) = if op == 0x24 {
                let g = b4;
                let cnt = a4;
                let second = u(pc + 2);
                let mut regs: Vec<u16> = Vec::with_capacity(cnt as usize);
                for i in 0..cnt {
                    let shift = 4 * i;
                    let r = if i == 4 {
                        g
                    } else {
                        (second >> shift) & 0xf
                    };
                    regs.push(r as u16);
                }
                (regs, u(pc + 1) as u32)
            } else {
                let cnt = aa;
                let first = u(pc + 2);
                (
                    (first..first + cnt).collect(),
                    u(pc + 1) as u32,
                )
            };
            return (
                3,
                InsnKind::FilledNewArray { regs, type_idx: idx },
            );
        }
        0x26 => {
            let off = i32of(pc + 1);
            return (
                3,
                InsnKind::FillArrayData { reg: aa as u16, payload_pc: (pc as i64 + off as i64) as u32 },
            );
        }

        // ---- control flow ----
        0x27 => InsnKind::Throw { reg: aa as u16 },
        0x28 => {
            return (
                1,
                InsnKind::Goto { target: (pc as i64 + aa as i8 as i64) as u32 },
            );
        }
        0x29 => {
            return (
                2,
                InsnKind::Goto { target: (pc as i64 + u(pc + 1) as i16 as i64) as u32 },
            );
        }
        0x2a => {
            return (
                3,
                InsnKind::Goto {
                    target: (pc as i64 + i32of(pc + 1) as i64) as u32,
                },
            );
        }
        0x2b => {
            let off = i32of(pc + 1);
            return (
                3,
                InsnKind::PackedSwitch {
                    reg: aa as u16,
                    payload_pc: (pc as i64 + off as i64) as u32,
                },
            );
        }
        0x2c => {
            let off = i32of(pc + 1);
            return (
                3,
                InsnKind::SparseSwitch {
                    reg: aa as u16,
                    payload_pc: (pc as i64 + off as i64) as u32,
                },
            );
        }
        0x2d..=0x31 => {
            let kind = match op {
                0x2d => CmpKind::CmplF,
                0x2e => CmpKind::CmpgF,
                0x2f => CmpKind::CmplD,
                0x30 => CmpKind::CmpgD,
                _ => CmpKind::CmpJ,
            };
            let second = u(pc + 1);
            return (
                2,
                InsnKind::Cmp {
                    dst: aa as u16,
                    a: (second & 0xff) as u16,
                    b: (second >> 8) as u16,
                    kind,
                },
            );
        }
        0x32..=0x37 => {
            let opkind = match op {
                0x32 => CmpOp::Eq,
                0x33 => CmpOp::Ne,
                0x34 => CmpOp::Lt,
                0x35 => CmpOp::Ge,
                0x36 => CmpOp::Gt,
                _ => CmpOp::Le,
            };
            let off = u(pc + 1) as i16 as i64 + pc as i64;
            return (
                2,
                InsnKind::If {
                    op: opkind,
                    a: b4 as u16,
                    b: a4 as u16,
                    z: false,
                    target: off as u32,
                },
            );
        }
        0x38..=0x3d => {
            let opkind = match op {
                0x38 => CmpOp::Eq,
                0x39 => CmpOp::Ne,
                0x3a => CmpOp::Lt,
                0x3b => CmpOp::Ge,
                0x3c => CmpOp::Gt,
                _ => CmpOp::Le,
            };
            let off = u(pc + 1) as i16 as i64 + pc as i64;
            return (
                2,
                InsnKind::If { op: opkind, a: aa as u16, b: 0, z: true, target: off as u32 },
            );
        }

        // ---- array element access (0x44-0x51) ----
        0x44..=0x51 => {
            let second = u(pc + 1);
            let r1 = aa as u16;
            let r2 = (second & 0xff) as u16;
            let r3 = (second >> 8) as u16;
            let is_load = op <= 0x4a;
            let ty = match op {
                0x44 | 0x4b => 'I',
                0x45 | 0x4c => 'J',
                0x46 | 0x4d => 'L',
                0x47 | 0x4e => 'Z',
                0x48 | 0x4f => 'B',
                0x49 | 0x50 => 'C',
                _ => 'S',
            };
            // 23x: TWO code units.
            if is_load {
                return (2, InsnKind::AGet { dst: r1, array: r2, index: r3, ty });
            } else {
                return (2, InsnKind::APut { value: r1, array: r2, index: r3, ty });
            }
        }

        // ---- instance fields (0x52-0x5f) ----
        0x52..=0x58 => {
            return (
                2,
                InsnKind::IGet {
                    dst: b4 as u16,
                    obj: a4 as u16,
                    field_idx: u(pc + 1) as u32,
                },
            );
        }
        0x59..=0x5f => {
            return (
                2,
                InsnKind::IPut {
                    value: b4 as u16,
                    obj: a4 as u16,
                    field_idx: u(pc + 1) as u32,
                },
            );
        }

        // ---- static fields (0x60-0x6d) ----
        0x60..=0x66 => {
            return (
                2,
                InsnKind::SGet { dst: aa as u16, field_idx: u(pc + 1) as u32 },
            );
        }
        0x67..=0x6d => {
            return (
                2,
                InsnKind::SPut { value: aa as u16, field_idx: u(pc + 1) as u32 },
            );
        }

        // ---- invoke-custom (0xfc/0xfd): BBBB is a call site index ----
        0xfc | 0xfd => {
            let cs_idx = u(pc + 1) as u32;
            let regs = if op == 0xfd {
                let cnt = aa;
                let first = u(pc + 2);
                (first..first + cnt).collect()
            } else {
                let cnt = a4;
                let g = b4;
                let second = u(pc + 2);
                let mut regs: Vec<u16> = Vec::with_capacity(cnt as usize);
                for i in 0..cnt {
                    let r = if i == 4 { g } else { (second >> (4 * i)) & 0xf };
                    regs.push(r as u16);
                }
                regs
            };
            return (3, InsnKind::InvokeCustom { call_site_idx: cs_idx, regs });
        }

        // ---- invokes ----
        0x6e..=0x72 | 0x74..=0x78 => {
            let kind = match op {
                0x6e | 0x74 => InvokeKind::Virtual,
                0x6f | 0x75 => InvokeKind::Super,
                0x70 | 0x76 => InvokeKind::Direct,
                0x71 | 0x77 => InvokeKind::Static,
                _ => InvokeKind::Interface,
            };
            let is_range = matches!(op, 0x74..=0x78);
            let idx = u(pc + 1) as u32;
            let regs = if is_range {
                let cnt = aa;
                let first = u(pc + 2);
                (first..first + cnt).collect()
            } else {
                let cnt = a4;
                let g = b4;
                let second = u(pc + 2);
                let mut regs: Vec<u16> = Vec::with_capacity(cnt as usize);
                for i in 0..cnt {
                    let r = if i == 4 { g } else { (second >> (4 * i)) & 0xf };
                    regs.push(r as u16);
                }
                regs
            };
            return (3, InsnKind::Invoke { kind, regs, method_idx: idx });
        }
        0xfa | 0xfb => {
            // invoke-polymorphic (45cc / 4rcc): treat as the base invoke,
            // dropping the trailing proto operand.
            let kind = InvokeKind::Polymorphic;
            let idx = u(pc + 1) as u32;
            let regs = if op == 0xfb {
                let cnt = aa;
                let first = u(pc + 3);
                (first..first + cnt).collect()
            } else {
                let cnt = a4;
                let g = b4;
                let second = u(pc + 2);
                let mut regs: Vec<u16> = Vec::with_capacity(cnt as usize);
                for i in 0..cnt {
                    let r = if i == 4 { g } else { (second >> (4 * i)) & 0xf };
                    regs.push(r as u16);
                }
                regs
            };
            return (4, InsnKind::Invoke { kind, regs, method_idx: idx });
        }
        0xfe => {
            return (
                2,
                InsnKind::ConstMethodHandle { dst: aa as u16, handle_idx: u(pc + 1) as u32 },
            );
        }
        0xff => {
            return (
                2,
                InsnKind::ConstMethodType { dst: aa as u16, proto_idx: u(pc + 1) as u32 },
            );
        }

        // ---- unary (0x7b-0x8f) ----
        0x7b..=0x8f => {
            let (opkind, from, to) = match op {
                0x7b => (UnArith::Neg, 'I', 'I'),
                0x7c => (UnArith::Not, 'I', 'I'),
                0x7d => (UnArith::Neg, 'J', 'J'),
                0x7e => (UnArith::Not, 'J', 'J'),
                0x7f => (UnArith::Neg, 'F', 'F'),
                0x80 => (UnArith::Neg, 'D', 'D'),
                0x81 => (UnArith::Conv, 'I', 'J'),
                0x82 => (UnArith::Conv, 'I', 'F'),
                0x83 => (UnArith::Conv, 'I', 'D'),
                0x84 => (UnArith::Conv, 'J', 'I'),
                0x85 => (UnArith::Conv, 'J', 'F'),
                0x86 => (UnArith::Conv, 'J', 'D'),
                0x87 => (UnArith::Conv, 'F', 'I'),
                0x88 => (UnArith::Conv, 'F', 'J'),
                0x89 => (UnArith::Conv, 'F', 'D'),
                0x8a => (UnArith::Conv, 'D', 'I'),
                0x8b => (UnArith::Conv, 'D', 'J'),
                0x8c => (UnArith::Conv, 'D', 'F'),
                0x8d => (UnArith::Conv, 'I', 'B'),
                0x8e => (UnArith::Conv, 'I', 'C'),
                _ => (UnArith::Conv, 'I', 'S'),
            };
            InsnKind::Un { dst: b4 as u16, src: a4 as u16, op: opkind, from, to }
        }

        // ---- three-register binops (0x90-0xaf, 23x) ----
        0x90..=0xaf => {
            let second = u(pc + 1);
            let (aop, ty) = bin3(op - 0x90);
            return (
                2,
                InsnKind::Bin {
                    op: aop,
                    dst: aa as u16,
                    a: (second & 0xff) as u16,
                    b: (second >> 8) as u16,
                    ty,
                },
            );
        }

        // ---- two-address binops (0xb0-0xcf, 12x) ----
        0xb0..=0xcf => {
            let (aop, ty) = bin3(op - 0xb0);
            InsnKind::Bin { op: aop, dst: b4 as u16, a: b4 as u16, b: a4 as u16, ty }
        }

        // ---- literal binops ----
        0xd0..=0xd7 => {
            let (aop, rsub) = binlit16(op - 0xd0);
            return (
                2,
                InsnKind::BinLit {
                    op: aop,
                    dst: b4 as u16,
                    a: a4 as u16,
                    lit: u(pc + 1) as i16 as i32,
                    rsub,
                },
            );
        }
        0xd8..=0xe2 => {
            let (aop, rsub) = binlit8(op - 0xd8);
            let second = u(pc + 1);
            let cc = (second >> 8) as i8;
            return (
                2,
                InsnKind::BinLit {
                    op: aop,
                    dst: aa as u16,
                    a: (second & 0xff) as u16,
                    lit: cc as i32,
                    rsub,
                },
            );
        }

        // ART-internal (return-void-no-barrier 0x73) / odex quickened / unused.
        _ => InsnKind::Unknown,
    };

    // One-unit formats default; two/three-unit ones returned early.
    (1, mk)
}

/// Maps a binop family offset to `(op, primitive)`.
/// Layout: int(8) + int-shifts(3) + long(8) + long-shifts(3) + float(5) +
/// double(5) — identical order for the 23x (0x90) and 2addr (0xb0) families.
fn bin3(off: u8) -> (ArithOp, char) {
    const OPS8: [ArithOp; 8] = [
        ArithOp::Add,
        ArithOp::Sub,
        ArithOp::Mul,
        ArithOp::Div,
        ArithOp::Rem,
        ArithOp::And,
        ArithOp::Or,
        ArithOp::Xor,
    ];
    const OPS5: [ArithOp; 5] = [
        ArithOp::Add,
        ArithOp::Sub,
        ArithOp::Mul,
        ArithOp::Div,
        ArithOp::Rem,
    ];
    match off {
        0..=7 => (OPS8[off as usize], 'I'),
        8..=10 => ([ArithOp::Shl, ArithOp::Shr, ArithOp::Ushr][(off - 8) as usize], 'I'),
        11..=18 => (OPS8[(off - 11) as usize], 'J'),
        19..=21 => ([ArithOp::Shl, ArithOp::Shr, ArithOp::Ushr][(off - 19) as usize], 'J'),
        22..=26 => (OPS5[(off - 22) as usize], 'F'),
        _ => (OPS5[(off - 27) as usize], 'D'),
    }
}

/// `binop/lit16` offset → op (+ rsub flag for reverse subtract).
fn binlit16(off: u8) -> (ArithOp, bool) {
    match off {
        0 => (ArithOp::Add, false),
        1 => (ArithOp::Sub, true), // rsub-int
        2 => (ArithOp::Mul, false),
        3 => (ArithOp::Div, false),
        4 => (ArithOp::Rem, false),
        5 => (ArithOp::And, false),
        6 => (ArithOp::Or, false),
        _ => (ArithOp::Xor, false),
    }
}

/// `binop/lit8` offset → op (+ rsub flag).
fn binlit8(off: u8) -> (ArithOp, bool) {
    match off {
        0 => (ArithOp::Add, false),
        1 => (ArithOp::Sub, true),
        2 => (ArithOp::Mul, false),
        3 => (ArithOp::Div, false),
        4 => (ArithOp::Rem, false),
        5 => (ArithOp::And, false),
        6 => (ArithOp::Or, false),
        7 => (ArithOp::Xor, false),
        8 => (ArithOp::Shl, false),
        9 => (ArithOp::Shr, false),
        _ => (ArithOp::Ushr, false),
    }
}

/// Instruction size (code units) by opcode — the full-format table from
/// the dalvik spec. Cross-checked against `decode_one`'s per-arm sizes by
/// the differential test below; the boundary walker (scan_instructions)
/// depends on it matching exactly.
pub fn opcode_units(op: u8) -> u32 {
    match op {
        0x00 => 1,
        0x01 | 0x04 | 0x07 => 1,
        0x02 | 0x05 | 0x08 => 2,
        0x03 | 0x06 | 0x09 => 3,
        0x0a..=0x12 => 1,
        0x13 | 0x15 | 0x16 | 0x19 => 2,
        0x14 | 0x17 => 3,
        0x18 => 5,
        0x1a | 0x1c => 2,
        0x1b => 3,
        0x1d | 0x1e | 0x21 | 0x27 | 0x28 => 1,
        0x1f | 0x20 | 0x22 | 0x23 => 2,
        0x24 | 0x25 | 0x26 => 3,
        0x29 => 2,
        0x2a => 3,
        0x2b | 0x2c => 2,
        0x2d..=0x37 => 2,
        0x38..=0x43 => 2,
        0x44..=0x6d => 2,
        0x6e..=0x72 => 3,
        0x73 => 1,
        0x74..=0x78 => 3,
        0x79 | 0x7a => 1,
        0x7b..=0x8a => 1,
        0x8b..=0x8f => 2,
        0x90..=0xaf => 2,
        0xb0..=0xcf => 1,
        0xd0..=0xe2 => 2,
        // invoke-custom (0xfc/0xfd, 35c/3rc) and method handle/type
        // constants (0xfe/0xff, 21c) are real format-3/2 instructions.
        0xfc | 0xfd => 3,
        0xfe | 0xff => 2,
        // remaining odex/unused: safest one-unit default keeps the walk
        // aligned with decode_all's degenerate handling.
        _ => 1,
    }
}

#[inline]
fn unit_at(bytes: &[u8], i: usize) -> u16 {
    if 2 * i + 1 < bytes.len() {
        u16::from_le_bytes([bytes[2 * i], bytes[2 * i + 1]])
    } else {
        0
    }
}

#[inline]
fn units_len(bytes: &[u8]) -> usize {
    bytes.len() / 2
}

/// Walk instruction BOUNDARIES only: `f(opcode, pc, insns_bytes)` fires for
/// every real instruction (payload pseudo-ops skipped), with the RAW insns
/// byte section for operand reads (`unit_at(bytes, pc + 1)` etc). No
/// InsnKind construction, no allocations — the reference-search scan path
/// (a full decode per instruction was the dominant cost).
pub fn scan_instructions<F: FnMut(u8, usize, &[u8])>(bytes: &[u8], f: &mut F) {
    let n = units_len(bytes);
    let mut pc = 0usize;
    while pc < n {
        let first = unit_at(bytes, pc);
        if first == 0x0100 || first == 0x0200 || first == 0x0300 {
            let size = payload_units_from_bytes(bytes, pc);
            pc += if size == 0 { 1 } else { size };
            continue;
        }
        let op = (first & 0xff) as u8;
        f(op, pc, bytes);
        pc += opcode_units(op).max(1) as usize;
    }
}

fn payload_units_from_bytes(bytes: &[u8], pc: usize) -> usize {
    let unit = |i: usize| -> u16 { unit_at(bytes, i) };
    match unit(pc) {
        0x0100 => 4 + unit(pc + 1) as usize * 2,
        0x0200 => 2 + unit(pc + 1) as usize * 4,
        0x0300 => {
            let width = unit(pc + 1) as usize;
            let size = (unit(pc + 2) as usize) | ((unit(pc + 3) as usize) << 16);
            4 + (size * width + 1) / 2
        }
        _ => 0,
    }
}

/// Decode a method body's unit stream: linear instructions + payloads map.
pub fn decode_all(bytes: &[u8]) -> (Vec<Insn>, HashMap<u32, Payload>) {
    let units = u16s(bytes);
    let mut insns = Vec::new();
    let mut payloads = HashMap::new();
    let mut pc = 0usize;
    while pc < units.len() {
        // Payload pseudo-instruction? (first unit is one of the idents.)
        let first = units[pc];
        if first == 0x0100 || first == 0x0200 || first == 0x0300 {
            let size = payload_units(bytes, pc);
            if size == 0 {
                // Malformed; treat as a one-unit nop so decoding continues.
                insns.push(Insn { pc: pc as u32, size: 1, op: 0, kind: InsnKind::Nop });
                pc += 1;
                continue;
            }
            if let Some(p) = parse_payload(bytes, pc) {
                payloads.insert(pc as u32, p);
            }
            pc += size;
            continue;
        }
        let (size, kind) = decode_one(&units, pc);
        let size = size.max(1);
        insns.push(Insn { pc: pc as u32, size, op: (units[pc] & 0xff) as u8, kind });
        pc += size as usize;
    }
    (insns, payloads)
}

/// Best-effort mnemonic for diagnostics.
pub fn op_name(op: u8) -> &'static str {
    match op {
        0x00 => "nop",
        0x01 => "move",
        0x02 => "move/from16",
        0x03 => "move/16",
        0x04 => "move-wide",
        0x05 => "move-wide/from16",
        0x06 => "move-wide/16",
        0x07 => "move-object",
        0x08 => "move-object/from16",
        0x09 => "move-object/16",
        0x0a => "move-result",
        0x0b => "move-result-wide",
        0x0c => "move-result-object",
        0x0d => "move-exception",
        0x0e => "return-void",
        0x0f => "return",
        0x10 => "return-wide",
        0x11 => "return-object",
        0x12 => "const/4",
        0x13 => "const/16",
        0x14 => "const",
        0x15 => "const/high16",
        0x16 => "const-wide/16",
        0x17 => "const-wide/32",
        0x18 => "const-wide",
        0x19 => "const-wide/high16",
        0x1a => "const-string",
        0x1b => "const-string/jumbo",
        0x1c => "const-class",
        0x1d => "monitor-enter",
        0x1e => "monitor-exit",
        0x1f => "check-cast",
        0x20 => "instance-of",
        0x21 => "array-length",
        0x22 => "new-instance",
        0x23 => "new-array",
        0x24 => "filled-new-array",
        0x25 => "filled-new-array/range",
        0x26 => "fill-array-data",
        0x27 => "throw",
        0x28 => "goto",
        0x29 => "goto/16",
        0x2a => "goto/32",
        0x2b => "packed-switch",
        0x2c => "sparse-switch",
        0x2d..=0x31 => "cmp",
        0x32..=0x3d => "if",
        0x44..=0x4a => "aget",
        0x4b..=0x51 => "aput",
        0x52..=0x58 => "iget",
        0x59..=0x5f => "iput",
        0x60..=0x66 => "sget",
        0x67..=0x6d => "sput",
        0x6e..=0x72 => "invoke",
        0x74..=0x78 => "invoke/range",
        0x7b..=0x8f => "unop",
        0x90..=0xaf => "binop",
        0xb0..=0xcf => "binop/2addr",
        0xd0..=0xd7 => "binop/lit16",
        0xd8..=0xe2 => "binop/lit8",
        0xfa | 0xfb => "invoke-polymorphic",
        0xfc | 0xfd => "invoke-custom",
        0xfe => "const-method-handle",
        0xff => "const-method-type",
        _ => "unknown",
    }
}

#[allow(dead_code)]
fn unused_format_units() {
    let _ = format_units(10);
    let _ = Cursor::new(&[]);
}
