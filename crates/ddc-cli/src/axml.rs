//! Minimal binary-XML (AXML) decoder: enough to render AndroidManifest.xml
//! from an APK back to readable XML.
//!
//! Chunk layout (absolute offsets inside each chunk):
//! - string pool  (0x0001, headerSize 0x1C): stringCount@8, styleCount@12,
//!   flags@16, stringsStart@20, stylesStart@24, offsets@28
//! - start elem   (0x0102, headerSize 0x10): ns@16, name@20, attrStart@24,
//!   attrSize@26, attrCount@28, attributes at 16+attrStart
//! - end elem     (0x0103, headerSize 0x18): ns@16, name@20
//! - cdata        (0x0104, headerSize 0x10): dataIdx@16

/// Render binary XML to indented text XML.
pub fn axml_to_xml(data: &[u8]) -> Result<String, String> {
    if data.len() < 8 {
        return Err("axml: too short".into());
    }
    let (typ, _hs, size) = (u16le(data, 0), u16le(data, 2), u32le(data, 4));
    if typ != 0x0003 {
        return Err(format!("axml: not a binary XML (first chunk 0x{typ:04x})"));
    }
    let end = (size as usize).min(data.len());
    let mut pos = 8usize;
    let mut out = String::new();
    let mut pool: Vec<String> = Vec::new();
    let mut depth = 0usize;
    let mut pending_text = String::new();

    while pos + 8 <= end {
        let typ = u16le(data, pos);
        let hs = u16le(data, pos + 2) as usize;
        let size = u32le(data, pos + 4) as usize;
        if size == 0 || hs > size {
            return Err("axml: bad chunk size".into());
        }
        let chunk_end = (pos + size).min(end);
        match typ {
            0x0001 => {
                pool = parse_string_pool(&data[pos..chunk_end])?;
            }
            0x0100 | 0x0101 => {} // start/end namespace
            0x0102 => {
                if chunk_end < pos + 36 {
                    return Err("axml: start element truncated".into());
                }
                let name_idx = i32at(data, pos + 20);
                let attr_start = u16le(data, pos + 24) as usize;
                let attr_size = u16le(data, pos + 26) as usize;
                let attr_count = u16le(data, pos + 28) as usize;
                let name = pool_get(&pool, name_idx)?;
                if !pending_text.trim().is_empty() {
                    out.push_str(&indent(depth));
                    out.push_str(&escape(pending_text.trim()));
                    out.push('\n');
                }
                pending_text.clear();
                out.push_str(&indent(depth));
                out.push('<');
                out.push_str(&name);
                // attributeStart is relative to the attrExt (chunk+16).
                let mut attrs = Vec::with_capacity(attr_count);
                let base = pos + 16 + attr_start;
                for i in 0..attr_count {
                    let o = base + i * attr_size;
                    if o + 20 > chunk_end {
                        break;
                    }
                    attrs.push(Attr {
                        name_idx: i32at(data, o + 4),
                        raw_value_idx: i32at(data, o + 8),
                        // Res_value: size u16, res0 u8, dataType u8, data u32
                        data_type: data[o + 15],
                        data: u32le(data, o + 16),
                    });
                }
                for a in &attrs {
                    let an = pool_get(&pool, a.name_idx)?;
                    out.push(' ');
                    out.push_str(&an);
                    out.push_str("=\"");
                    out.push_str(&escape(&render_value(a, &pool)?));
                    out.push('"');
                }
                out.push_str(">\n");
                depth += 1;
            }
            0x0103 => {
                if chunk_end < pos + 24 {
                    return Err("axml: end element truncated".into());
                }
                let name = pool_get(&pool, i32at(data, pos + 20))?;
                depth = depth.saturating_sub(1);
                if !pending_text.trim().is_empty() {
                    out.push_str(&indent(depth));
                    out.push_str(&escape(pending_text.trim()));
                    out.push('\n');
                    pending_text.clear();
                }
                out.push_str(&indent(depth));
                out.push_str("</");
                out.push_str(&name);
                out.push_str(">\n");
            }
            0x0104 => {
                if chunk_end >= pos + 20 {
                    pending_text.push_str(&pool_get(&pool, i32at(data, pos + 16))?);
                }
            }
            _ => {} // resource map (0x0180) etc.
        }
        pos = chunk_end;
    }
    Ok(out)
}

fn u16le(d: &[u8], o: usize) -> u16 {
    u16::from_le_bytes([d[o], d[o + 1]])
}
fn u32le(d: &[u8], o: usize) -> u32 {
    u32::from_le_bytes([d[o], d[o + 1], d[o + 2], d[o + 3]])
}
fn i32at(d: &[u8], o: usize) -> i32 {
    i32::from_le_bytes([d[o], d[o + 1], d[o + 2], d[o + 3]])
}

fn indent(depth: usize) -> String {
    "    ".repeat(depth)
}

fn escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '&' => out.push_str("&amp;"),
            '"' => out.push_str("&quot;"),
            _ => out.push(c),
        }
    }
    out
}

fn pool_get(pool: &[String], idx: i32) -> Result<String, String> {
    if idx < 0 {
        return Ok(String::new());
    }
    pool.get(idx as usize)
        .cloned()
        .ok_or_else(|| format!("bad string index {idx}"))
}

struct Attr {
    name_idx: i32,
    raw_value_idx: i32,
    data_type: u8,
    data: u32,
}

/// AAPT string pool: UTF-16 default, UTF-8 when flag 0x100.
fn parse_string_pool(chunk: &[u8]) -> Result<Vec<String>, String> {
    if chunk.len() < 28 {
        return Err("string pool too short".into());
    }
    let string_count = u32le(chunk, 8) as usize;
    let flags = u32le(chunk, 16);
    let strings_start = u32le(chunk, 20) as usize;
    let is_utf8 = flags & 0x100 != 0;
    let mut out = Vec::with_capacity(string_count.min(1 << 20));
    for i in 0..string_count {
        let off_at = 28 + i * 4;
        if off_at + 4 > chunk.len() {
            return Err("string pool offsets truncated".into());
        }
        let o = strings_start + u32le(chunk, off_at) as usize;
        if o >= chunk.len() {
            out.push(String::new());
            continue;
        }
        out.push(read_pool_str(&chunk[o..], is_utf8)?);
    }
    Ok(out)
}

fn read_pool_str(d: &[u8], utf8: bool) -> Result<String, String> {
    if utf8 {
        // u8 char count (length-encoded), u8 byte count, bytes, NUL.
        let (_chars, d) = read_u8_len(d);
        let (bytes, d) = read_u8_len(d);
        let take = bytes.min(d.len());
        Ok(String::from_utf8_lossy(&d[..take]).into_owned())
    } else {
        // u16 char count (high bit = extended), UTF-16LE, NUL.
        let (chars, d) = read_u16_len(d)?;
        let bytes = chars.saturating_mul(2).min(d.len());
        let mut u16s = Vec::with_capacity(bytes / 2);
        for i in 0..bytes / 2 {
            u16s.push(u16::from_le_bytes([d[i * 2], d[i * 2 + 1]]));
        }
        Ok(String::from_utf16_lossy(&u16s))
    }
}

fn read_u8_len(d: &[u8]) -> (usize, &[u8]) {
    if d.is_empty() {
        return (0, d);
    }
    let b = d[0] as usize;
    if b & 0x80 != 0 && d.len() > 1 {
        ((((b & 0x7f) as usize) << 8) | d[1] as usize, &d[2..])
    } else {
        (b, &d[1..])
    }
}

fn read_u16_len(d: &[u8]) -> Result<(usize, &[u8]), String> {
    if d.len() < 2 {
        return Err("utf16 length truncated".into());
    }
    let w = u16le(d, 0) as usize;
    if w & 0x8000 != 0 {
        if d.len() < 4 {
            return Err("utf16 extended length truncated".into());
        }
        Ok((((w & 0x7fff) << 16) | u16le(d, 2) as usize, &d[4..]))
    } else {
        Ok((w, &d[2..]))
    }
}

/// android.util.TypedValue data types (subset seen in manifests).
const TYPE_REFERENCE: u8 = 0x01;
const TYPE_FLOAT: u8 = 0x04;
const TYPE_STRING: u8 = 0x03;
const TYPE_INT_DEC: u8 = 0x10;
const TYPE_INT_HEX: u8 = 0x11;
const TYPE_INT_BOOLEAN: u8 = 0x12;

fn render_value(a: &Attr, pool: &[String]) -> Result<String, String> {
    if a.raw_value_idx >= 0 {
        if let Some(s) = pool.get(a.raw_value_idx as usize) {
            return Ok(s.clone());
        }
    }
    match a.data_type {
        TYPE_STRING => pool_get(pool, a.data as i32),
        TYPE_REFERENCE => Ok(format!("@0x{:08x}", a.data)),
        TYPE_INT_BOOLEAN => Ok(if a.data != 0 { "true".into() } else { "false".into() }),
        TYPE_INT_HEX => Ok(format!("0x{:x}", a.data as i32)),
        TYPE_INT_DEC => Ok((a.data as i32).to_string()),
        TYPE_FLOAT => Ok(format!("{:.6}", f32::from_bits(a.data))),
        _ => Ok(format!("0x{:08x}", a.data)),
    }
}
