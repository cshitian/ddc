//! Minimal `resources.arsc` reader: resolves ONE `@0x…` reference to its
//! string value (the application label and friends live behind those refs
//! once AAPT2 strips literal strings from the manifest).
//!
//! Layout walk (only what a string lookup needs):
//! table header (`RES_TABLE_TYPE`) → global string pool
//! (`RES_STRING_POOL_TYPE`) → package chunks (`0x0200`, id `u32@8`) →
//! type chunks (`0x0201`: id `u8@8`, flags `u8@9` — bit 0 is SPARSE,
//! entryCount `u32@12`, entriesStart `u32@16`) → entry (size, flags, key)
//! → `Res_value` (dataType `u8`, data `u32`; type 3 = STRING → global
//! pool index). Any miss returns `None` — the caller keeps the raw ref.

use std::path::Path;

/// Decode a string pool chunk (UTF-8 flag `0x100`, or UTF-16 otherwise).
fn string_pool(data: &[u8], off: usize) -> Option<Vec<String>> {
    if off + 28 > data.len() {
        return None;
    }
    let rd_u16 = |p: usize| u16::from_le_bytes(data[p..p + 2].try_into().unwrap());
    let rd_u32 = |p: usize| u32::from_le_bytes(data[p..p + 4].try_into().unwrap());
    let hdr = rd_u16(off + 2) as usize;
    let count = rd_u32(off + 8) as usize;
    let flags = rd_u32(off + 16);
    let str_start = rd_u32(off + 20) as usize;
    let utf8 = flags & 0x100 != 0;
    let base = off + str_start;
    let mut out = Vec::with_capacity(count);
    for i in 0..count {
        let at = off + hdr + 4 * i;
        if at + 4 > data.len() {
            break;
        }
        let p = base + rd_u32(at) as usize;
        let s = if utf8 {
            // uleb8-style length pair: (chars, bytes), each u8 or
            // two-byte extended (high bit = high half).
            let mut q = p;
            // char length (ignored — the byte length below sizes the read)
            let clen = data.get(q).copied().unwrap_or(0) as usize;
            q += 1;
            if clen & 0x80 != 0 {
                q += 1;
            }
            let mut n2 = data.get(q).copied().unwrap_or(0) as usize;
            q += 1;
            if n2 & 0x80 != 0 {
                n2 = ((n2 & 0x7f) << 8) | data.get(q).copied().unwrap_or(0) as usize;
                q += 1;
            }
            String::from_utf8_lossy(data.get(q..q + n2).unwrap_or(&[])).into_owned()
        } else {
            let mut q = p;
            let mut n = rd_u16(q) as usize;
            q += 2;
            if n & 0x8000 != 0 {
                n = ((n & 0x7fff) << 16) | rd_u16(q) as usize;
                q += 2;
            }
            let bytes = data.get(q..q + n * 2).unwrap_or(&[]);
            let units: Vec<u16> = bytes
                .as_chunks::<2>()
                .0
                .iter()
                .map(|c| u16::from_le_bytes([c[0], c[1]]))
                .collect();
            String::from_utf16_lossy(&units)
        };
        out.push(s);
    }
    Some(out)
}

/// Walk one arsc image for a resource id's string value.
fn resolve_in_arsc(data: &[u8], res_id: u32) -> Option<String> {
    let rd_u16 = |p: usize| -> Option<u16> {
        Some(u16::from_le_bytes(data.get(p..p + 2)?.try_into().ok()?))
    };
    let rd_u32 = |p: usize| -> Option<u32> {
        Some(u32::from_le_bytes(data.get(p..p + 4)?.try_into().ok()?))
    };
    let pkg_id = res_id >> 24;
    let type_id = ((res_id >> 16) & 0xff) as u8;
    let entry_id = (res_id & 0xffff) as usize;
    let hdr = rd_u16(2)? as usize;
    let pool_off = if hdr > 0 { hdr } else { 12 };
    let pool_size = rd_u32(pool_off + 4)? as usize;
    let gpool = string_pool(data, pool_off)?;
    let mut p = pool_off + pool_size;
    while p + 12 <= data.len() {
        let ctyp = rd_u16(p)?;
        let chdr = rd_u16(p + 2)? as usize;
        let csize = rd_u32(p + 4)? as usize;
        if csize == 0 || p + csize > data.len() {
            return None;
        }
        if ctyp == 0x0200 && rd_u32(p + 8)? == pkg_id {
            let mut q = p + chdr;
            while q + 20 <= p + csize {
                let ityp = rd_u16(q)?;
                let ihdr = rd_u16(q + 2)? as usize;
                let isize = rd_u32(q + 4)? as usize;
                if isize == 0 || isize < ihdr || q + isize > data.len() {
                    return None;
                }
                if ityp == 0x0201 && data.get(q + 8).copied() == Some(type_id) {
                    // Entry lookup as a nested block: every miss simply
                    // FALLS THROUGH to the chunk advance below — a
                    // `continue` here would skip it and spin forever on
                    // the miss cases.
                    let es = rd_u32(q + 16)? as usize;
                    let entry = (|| -> Option<usize> {
                        let flags = data.get(q + 9).copied().unwrap_or(0);
                        let ec = rd_u32(q + 12)? as usize;
                        if flags & 0x01 != 0 {
                            // sparse: (idx << 16 | offset) u32s
                            for i in 0..ec {
                                let at = q + ihdr + 4 * i;
                                if at + 4 > data.len() {
                                    break;
                                }
                                let v = rd_u32(at)?;
                                if (v >> 16) as usize == entry_id {
                                    return Some((v & 0xffff) as usize);
                                }
                            }
                            None
                        } else if entry_id < ec {
                            let at = q + ihdr + 4 * entry_id;
                            let v = rd_u32(at)?;
                            if v == 0xffff_ffff {
                                None
                            } else {
                                Some(v as usize)
                            }
                        } else {
                            None
                        }
                    })();
                    if let Some(entry_off) = entry {
                        let e = q + es + entry_off;
                        if e + 12 <= data.len() {
                            let eflags = rd_u16(e + 2)?;
                            if eflags & 0x0001 == 0 {
                                // Res_value at entry + 8: u16 size, u8
                                // res0, u8 dataType, u32 data.
                                let dtype = data.get(e + 11).copied().unwrap_or(0);
                                let dval = rd_u32(e + 12)?;
                                if dtype == 0x03 {
                                    return gpool.get(dval as usize).cloned();
                                }
                            }
                        }
                    }
                }
                q += isize;
            }
        }
        p += csize;
    }
    None
}

/// Resolve `@0x…` (from a manifest attribute) to its string. Looks for
/// `resources.arsc` in the top-level zip, then in the container's
/// base-first APKs — mirroring `manifest_bytes`'s lookup order.
pub(crate) fn resolve_string_ref(input: &Path, r: &str) -> Option<String> {
    let hex = r.trim_start_matches('@').trim_start_matches("0x");
    let res_id = u32::from_str_radix(hex, 16).ok()?;
    let src = crate::inputs::map_source(input).ok()?;
    let bytes: &[u8] = src.bytes();
    if bytes.len() < 4 || &bytes[..2] != b"PK" {
        return None;
    }
    let entries = crate::zip_entries(bytes).ok()?;
    for e in entries.iter().filter(|e| e.name == "resources.arsc") {
        if let Ok(raw) = crate::manifest::entry_bytes(bytes, e) {
            if let Some(s) = resolve_in_arsc(&raw, res_id) {
                return Some(s);
            }
        }
    }
    // Container: base APK first (label lives beside the manifest).
    let stem = input.file_stem().and_then(|s| s.to_str()).unwrap_or("");
    let mut apks: Vec<&crate::ZipEntry> =
        entries.iter().filter(|e| e.name.ends_with(".apk")).collect();
    apks.sort_by_key(|e| {
        let base = e.name == "base.apk"
            || e.name == format!("{stem}.apk")
            || e.name.starts_with("split_base");
        (!base, e.name.clone())
    });
    for apk in apks {
        if let Ok(inner) = crate::manifest::entry_bytes(bytes, apk) {
            if inner.len() < 4 || &inner[..2] != b"PK" {
                continue;
            }
            if let Ok(ies) = crate::zip_entries(&inner) {
                for e in ies.iter().filter(|e| e.name == "resources.arsc") {
                    if let Ok(raw) = crate::manifest::entry_bytes(&inner, e) {
                        if let Some(s) = resolve_in_arsc(&raw, res_id) {
                            return Some(s);
                        }
                    }
                }
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Hand-build a one-string arsc: table header → global UTF-8 pool →
    /// package 0x7f → type 1 → entry 0 → Res_value STRING → pool[0].
    fn one_string_arsc(s: &str) -> Vec<u8> {
        let mut pool = Vec::new();
        // string item: u8 char-len, u8 byte-len, bytes, NUL
        let bytes = s.as_bytes();
        pool.push(bytes.len() as u8);
        pool.push(bytes.len() as u8);
        pool.extend_from_slice(bytes);
        pool.push(0);
        let count = 1usize;
        let str_start = 28 + 4 * count;
        while pool.len() % 4 != 0 {
            pool.push(0);
        }
        let pool_size = str_start + pool.len();
        let mut arsc = Vec::new();
        // table header: type 0x0002, headerSize 12 (chunk 8 +
        // packageCount u32), size patched later
        arsc.extend_from_slice(&2u16.to_le_bytes());
        arsc.extend_from_slice(&12u16.to_le_bytes());
        arsc.extend_from_slice(&0u32.to_le_bytes());
        arsc.extend_from_slice(&1u32.to_le_bytes()); // packageCount
        // string pool: type 1, hdr 28, size, count, styles 0, flags 0x100
        arsc.extend_from_slice(&1u16.to_le_bytes());
        arsc.extend_from_slice(&28u16.to_le_bytes());
        arsc.extend_from_slice(&(pool_size as u32).to_le_bytes());
        arsc.extend_from_slice(&(count as u32).to_le_bytes());
        arsc.extend_from_slice(&0u32.to_le_bytes());
        arsc.extend_from_slice(&0x100u32.to_le_bytes());
        arsc.extend_from_slice(&(str_start as u32).to_le_bytes());
        arsc.extend_from_slice(&0u32.to_le_bytes());
        arsc.extend_from_slice(&0u32.to_le_bytes()); // offset[0]
        arsc.extend_from_slice(&pool);
        // package chunk: type 0x0200, headerSize 288, id 0x7f
        let type_chunk = {
            // type 0x0201: hdr 84, entryCount 1, entriesStart 88 (right
            // past the offset array), dense offset[0]=0, entry: size 8,
            // flags 0, key 0; value: size 8, res0 0, dtype 3, data 0.
            let mut t = Vec::new();
            t.extend_from_slice(&0x0201u16.to_le_bytes());
            t.extend_from_slice(&84u16.to_le_bytes());
            t.extend_from_slice(&0u32.to_le_bytes()); // size (patched)
            t.push(1); // type id
            t.push(0); // flags: dense
            t.extend_from_slice(&0u16.to_le_bytes());
            t.extend_from_slice(&1u32.to_le_bytes()); // entryCount
            t.extend_from_slice(&88u32.to_le_bytes()); // entriesStart
            t.extend_from_slice(&[0u8; 64]); // config filler to hdr 84
            t.extend_from_slice(&0u32.to_le_bytes()); // offset[0] = 0
            t.extend_from_slice(&8u16.to_le_bytes()); // entry size
            t.extend_from_slice(&0u16.to_le_bytes()); // entry flags
            t.extend_from_slice(&0u32.to_le_bytes()); // key
            t.extend_from_slice(&8u16.to_le_bytes()); // value size
            t.push(0); // res0
            t.push(3); // dataType STRING
            t.extend_from_slice(&0u32.to_le_bytes()); // data = pool[0]
            let total = t.len();
            t[4..8].copy_from_slice(&(total as u32).to_le_bytes());
            t
        };
        let pkg_size = 288 + type_chunk.len();
        arsc.extend_from_slice(&0x0200u16.to_le_bytes());
        arsc.extend_from_slice(&288u16.to_le_bytes());
        arsc.extend_from_slice(&(pkg_size as u32).to_le_bytes());
        arsc.extend_from_slice(&0x7fu32.to_le_bytes());
        arsc.extend_from_slice(&[0u8; 256]); // package name
        arsc.extend_from_slice(&[0u8; 20]); // typeStrings/keyStrings etc.
        arsc.extend_from_slice(&type_chunk);
        let total = arsc.len();
        arsc[4..8].copy_from_slice(&(total as u32).to_le_bytes());
        arsc
    }

    #[test]
    fn resolves_string_ref() {
        let arsc = one_string_arsc("MyApp");
        assert_eq!(
            resolve_in_arsc(&arsc, 0x7f010000),
            Some("MyApp".to_string())
        );
        // Misses stay None (wrong entry / wrong type / wrong package).
        assert_eq!(resolve_in_arsc(&arsc, 0x7f010001), None);
        assert_eq!(resolve_in_arsc(&arsc, 0x7f020000), None);
        assert_eq!(resolve_in_arsc(&arsc, 0x10010000), None);
    }
}
