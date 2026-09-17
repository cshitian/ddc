//! `encoded_value`, annotations and static-value arrays.
//!
//! Only what the decompiler needs: static field initializers and the
//! dalvik nesting annotations (`EnclosingClass`, `InnerClass`,
//! `EnclosingMethod`, `MemberClasses`).

use crate::reader::Cursor;

#[derive(Debug, Clone)]
pub enum EncodedValue {
    Byte(i8),
    Short(i16),
    Char(u16),
    Int(i32),
    Long(i64),
    Float(f32),
    Double(f64),
    MethodType(u32),
    MethodHandle(u32),
    String(u32),
    Type(u32),
    Field(u32),
    Method(u32),
    Enum(u32),
    Array(Vec<EncodedValue>),
    Annotation(EncodedAnnotation),
    Null,
    Boolean(bool),
}

#[derive(Debug, Clone)]
pub struct EncodedAnnotation {
    pub type_idx: u32,
    /// (name string idx, value)
    pub elements: Vec<(u32, EncodedValue)>,
}

fn little_extend(bytes: &[u8], signed: bool, size: usize) -> i64 {
    let mut v: u64 = 0;
    for (i, &b) in bytes.iter().enumerate() {
        v |= (b as u64) << (8 * i);
    }
    if signed {
        let shift = 64 - 8 * size;
        v = (v << shift) as i64 as u64 >> shift;
    }
    v as i64
}

pub fn read_encoded_value(data: &[u8], pos: usize) -> Option<(EncodedValue, usize)> {
    let mut c = Cursor::at(data, pos);
    let header = c.u1()?;
    let vtype = header & 0x1f;
    let varg = (header >> 5) as usize;
    match vtype {
        0x00 => {
            let v = little_extend(&take(data, c.pos, varg + 1)?, true, varg + 1);
            Some((EncodedValue::Byte(v as i8), c.pos + varg + 1 - pos))
        }
        0x02 => {
            let v = little_extend(&take(data, c.pos, varg + 1)?, true, varg + 1);
            Some((EncodedValue::Short(v as i16), c.pos + varg + 1 - pos))
        }
        0x03 => {
            let v = little_extend(&take(data, c.pos, varg + 1)?, false, varg + 1);
            Some((EncodedValue::Char(v as u16), c.pos + varg + 1 - pos))
        }
        0x04 => {
            let v = little_extend(&take(data, c.pos, varg + 1)?, true, varg + 1);
            Some((EncodedValue::Int(v as i32), c.pos + varg + 1 - pos))
        }
        0x06 => {
            let v = little_extend(&take(data, c.pos, varg + 1)?, true, varg + 1);
            Some((EncodedValue::Long(v), c.pos + varg + 1 - pos))
        }
        0x10 => {
            let v = little_extend(&take(data, c.pos, varg + 1)?, false, varg + 1);
            Some((
                EncodedValue::Float(f32::from_bits(v as u32)),
                c.pos + varg + 1 - pos,
            ))
        }
        0x11 => {
            let v = little_extend(&take(data, c.pos, varg + 1)?, false, varg + 1);
            Some((
                EncodedValue::Double(f64::from_bits(v as u64)),
                c.pos + varg + 1 - pos,
            ))
        }
        0x15 | 0x16 | 0x17 | 0x18 | 0x19 | 0x1a | 0x1b => {
            let v = little_extend(&take(data, c.pos, varg + 1)?, false, varg + 1);
            let ev = match vtype {
                0x15 => EncodedValue::MethodType(v as u32),
                0x16 => EncodedValue::MethodHandle(v as u32),
                0x17 => EncodedValue::String(v as u32),
                0x18 => EncodedValue::Type(v as u32),
                0x19 => EncodedValue::Field(v as u32),
                0x1a => EncodedValue::Method(v as u32),
                _ => EncodedValue::Enum(v as u32),
            };
            Some((ev, c.pos + varg + 1 - pos))
        }
        0x1c => {
            let n = c.read_uleb128()? as usize;
            let mut items = Vec::with_capacity(n);
            let mut p = c.pos;
            for _ in 0..n {
                let (v, used) = read_encoded_value(data, p)?;
                p += used;
                items.push(v);
            }
            Some((EncodedValue::Array(items), p - pos))
        }
        0x1d => {
            let (a, used) = read_encoded_annotation(data, c.pos)?;
            Some((EncodedValue::Annotation(a), c.pos - pos + used))
        }
        0x1e => Some((EncodedValue::Null, 1)),
        0x1f => Some((EncodedValue::Boolean(varg != 0), 1)),
        _ => Some((EncodedValue::Null, 1)),
    }
}

fn take(data: &[u8], pos: usize, n: usize) -> Option<&[u8]> {
    if pos + n > data.len() {
        return None;
    }
    Some(&data[pos..pos + n])
}

pub fn read_encoded_annotation(data: &[u8], pos: usize) -> Option<(EncodedAnnotation, usize)> {
    let mut c = Cursor::at(data, pos);
    let type_idx = c.read_uleb128()? as u32;
    let n = c.read_uleb128()? as usize;
    let mut elements = Vec::with_capacity(n);
    let mut p = c.pos;
    for _ in 0..n {
        let mut cc = Cursor::at(data, p);
        let name = cc.read_uleb128()? as u32;
        p = cc.pos;
        let (v, used) = read_encoded_value(data, p)?;
        p += used;
        elements.push((name, v));
    }
    Some((EncodedAnnotation { type_idx, elements }, p - pos))
}

pub fn read_encoded_array(data: &[u8], pos: usize) -> Option<Vec<EncodedValue>> {
    let mut c = Cursor::at(data, pos);
    let n = c.read_uleb128()? as usize;
    let mut out = Vec::with_capacity(n);
    let mut p = c.pos;
    for _ in 0..n {
        let (v, used) = read_encoded_value(data, p)?;
        p += used;
        out.push(v);
    }
    Some(out)
}

/// `annotation_directory_item` → `class_annotations_off` → annotation set:
/// all annotations attached to a class.
pub fn read_class_annotations(data: &[u8], annotations_off: u32) -> Vec<EncodedAnnotation> {
    let off = annotations_off as usize;
    if off == 0 || off + 4 > data.len() {
        return Vec::new();
    }
    let set_off = u32::from_le_bytes(data[off..off + 4].try_into().unwrap()) as usize;
    if set_off == 0 || set_off + 4 > data.len() {
        return Vec::new();
    }
    let n = u32::from_le_bytes(data[set_off..set_off + 4].try_into().unwrap()) as usize;
    let mut out = Vec::with_capacity(n);
    for i in 0..n {
        let p = set_off + 4 + 4 * i;
        if p + 4 > data.len() {
            break;
        }
        let item_off = u32::from_le_bytes(data[p..p + 4].try_into().unwrap()) as usize;
        // annotation_item: u1 visibility + encoded_annotation.
        if item_off >= data.len() {
            continue;
        }
        if let Some((a, _)) = read_encoded_annotation(data, item_off + 1) {
            out.push(a);
        }
    }
    out
}

/// Nesting evidence recorded by d8 in dalvik annotations.
#[derive(Debug, Clone, Default)]
pub struct NestingInfo {
    /// `Ldalvik/annotation/EnclosingClass;` → outer type idx.
    pub enclosing_class: Option<u32>,
    /// `Ldalvik/annotation/EnclosingMethod;` → method idx.
    pub enclosing_method: Option<u32>,
    /// `Ldalvik/annotation/InnerClass;` → simple name.
    pub inner_name: Option<u32>,
    /// `Ldalvik/annotation/MemberClasses;` → member type idxs.
    pub member_classes: Vec<u32>,
}

const DALVIK_ENCLOSING_CLASS: &str = "Ldalvik/annotation/EnclosingClass;";
const DALVIK_ENCLOSING_METHOD: &str = "Ldalvik/annotation/EnclosingMethod;";
const DALVIK_INNER_CLASS: &str = "Ldalvik/annotation/InnerClass;";
const DALVIK_MEMBER_CLASSES: &str = "Ldalvik/annotation/MemberClasses;";

/// Resolve nesting from class annotations given a dex string resolver.
pub fn nesting_from(
    annotations: &[EncodedAnnotation],
    type_name: &dyn Fn(u32) -> String,
) -> NestingInfo {
    let mut info = NestingInfo::default();
    for a in annotations {
        let tname = type_name(a.type_idx);
        match tname.as_str() {
            DALVIK_ENCLOSING_CLASS => {
                for (_, v) in &a.elements {
                    if let EncodedValue::Type(t) = v {
                        info.enclosing_class = Some(*t);
                    }
                }
            }
            DALVIK_ENCLOSING_METHOD => {
                for (_, v) in &a.elements {
                    if let EncodedValue::Method(m) = v {
                        info.enclosing_method = Some(*m);
                    }
                }
            }
            DALVIK_INNER_CLASS => {
                for (_, v) in &a.elements {
                    if let EncodedValue::String(s) = v {
                        info.inner_name = Some(*s);
                    }
                }
            }
            DALVIK_MEMBER_CLASSES => {
                for (_, v) in &a.elements {
                    if let EncodedValue::Array(items) = v {
                        for it in items {
                            if let EncodedValue::Type(t) = it {
                                info.member_classes.push(*t);
                            }
                        }
                    }
                }
            }
            _ => {}
        }
    }
    info
}
