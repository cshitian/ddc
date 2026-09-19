//! Platform symbols: render IntDef/LongDef magic numbers as their
//! constant names (`view.setVisibility(8)` → `android.view.View.GONE`).
//!
//! Two inputs, both from an Android SDK platform directory:
//! * `android.jar` — classfile `ConstantValue` attributes give every
//!   static final field's value (`android.view.View.GONE = 8`).
//! * `data/annotations.zip` — per-method-parameter `@IntDef`/`@LongDef`
//!   domains as `annotations.xml` items (the SDK's metalava metadata —
//!   the jar itself does not retain them).
//!
//! A call site rewrites only on an EXACT domain match: flag domains
//! (combinable values such as Intent flags) stay numeric for combined
//! literals and render named for single values.

use std::collections::HashMap;
use std::sync::OnceLock;

/// One constant domain: members (owner, field, value).
#[derive(Debug, Clone)]
struct ConstantDomain {
    members: Vec<(String, String, i64)>,
}

impl ConstantDomain {
    /// The member whose value matches exactly, when exactly one does —
    /// duplicate values stay numeric (ambiguous beats wrong).
    fn exact(&self, value: i64) -> Option<&(String, String, i64)> {
        let mut hit = None;
        for m in &self.members {
            if m.2 == value {
                if hit.is_some() {
                    return None;
                }
                hit = Some(m);
            }
        }
        hit
    }
}

#[derive(Debug, Default)]
pub struct PlatformSymbols {
    /// (class, method, descriptor) → per-argument domains.
    domains: HashMap<(String, String, String), Vec<Option<ConstantDomain>>>,
}

static SYMBOLS: OnceLock<PlatformSymbols> = OnceLock::new();

/// Install the symbols for this run (from the driver, before workers
/// start — same pattern as the case-rename registry).
pub fn set_symbols(s: PlatformSymbols) {
    let _ = SYMBOLS.set(s);
}

/// Whether symbols are installed (the pass gates on this).
pub fn installed() -> bool {
    SYMBOLS.get().is_some_and(|s| !s.domains.is_empty())
}

/// The named constant for a call argument, when the platform knows the
/// parameter's domain and the literal matches exactly one member.
/// Rendered dotted-and-qualified (the output has no imports).
pub fn named_constant(cls: &str, name: &str, desc: &str, arg: usize, value: i64) -> Option<String> {
    let syms = SYMBOLS.get()?;
    if syms.domains.is_empty() {
        return None;
    }
    let per_arg = syms.domains.get(&(cls.to_string(), name.to_string(), desc.to_string()))?;
    let domain = per_arg.get(arg).or_else(|| per_arg.first()).cloned().flatten()?;
    let (owner, field, _) = domain.exact(value)?;
    Some(format!("{}.{}", owner.replace('/', "."), field))
}

impl PlatformSymbols {
    /// Build from `annotations.xml` byte slices plus the resolved
    /// constants ((class, field) → value) off android.jar.
    pub fn from_metadata(xmls: &[&[u8]], constants: &HashMap<(String, String), i64>) -> Self {
        let mut domains: HashMap<(String, String, String), Vec<Option<ConstantDomain>>> =
            HashMap::new();
        let mut on_domain = |class: &str, method: &str, desc: &str, param: usize,
                             ann: &str, value: &str| {
            if !ann.contains("IntDef") && !ann.contains("LongDef") {
                return;
            }
            // `{android.view.View.VISIBLE, android.view.View.GONE}`
            let members: Vec<(String, String, i64)> = value
                .trim_matches(|c| c == '{' || c == '}')
                .split(',')
                .filter_map(|m| {
                    let m = m.trim();
                    let (owner, field) = m.rsplit_once('.')?;
                    let owner = owner.replace('.', "/");
                    let v = constants.get(&(owner.clone(), field.to_string()))?;
                    Some((owner, field.to_string(), *v))
                })
                .collect();
            if members.is_empty() {
                return;
            }
            let entry = domains
                .entry((class.to_string(), method.to_string(), desc.to_string()))
                .or_default();
            while entry.len() <= param {
                entry.push(None);
            }
            entry[param] = Some(ConstantDomain { members });
        };
        for xml in xmls {
            parse_annotations_xml(xml, &mut on_domain);
        }
        Self { domains }
    }

    /// Number of methods carrying at least one constant domain.
    pub fn domain_count(&self) -> usize {
        self.domains.values().filter(|v| v.iter().any(|d| d.is_some())).count()
    }
}

/// Java source type → dex descriptor fragment (`int` → `I`,
/// `android.view.View` → `Landroid/view/View;`, `int[]` → `[I`).
fn java_type_to_dex(t: &str) -> String {
    let t = t.trim();
    if let Some(inner) = t.strip_suffix("[]") {
        return format!("[{}", java_type_to_dex(inner));
    }
    let prim = match t {
        "void" => "V",
        "int" => "I",
        "long" => "J",
        "float" => "F",
        "double" => "D",
        "boolean" => "Z",
        "byte" => "B",
        "char" => "C",
        "short" => "S",
        _ => "",
    };
    if !prim.is_empty() {
        return prim.to_string();
    }
    if t.is_empty() {
        return String::new();
    }
    format!("L{};", t.replace('.', "/"))
}

/// Line-level walk of a metalava `annotations.xml`: items nest regularly
/// (`<item name=…><annotation name=…><val name="value" val="{…}"/>`) —
/// the same line-attr parsing style manifest.rs uses.
/// (class, method, descriptor, param index, annotation, value).
type DomainSink<'a> = dyn FnMut(&str, &str, &str, usize, &str, &str) + 'a;

fn parse_annotations_xml(xml: &[u8], on_domain: &mut DomainSink<'_>) {
    let text = String::from_utf8_lossy(xml);
    let attr = |line: &str, key: &str| -> Option<String> {
        let pat = format!("{key}=\"");
        let start = line.find(&pat)? + pat.len();
        let end = line[start..].find('"')? + start;
        Some(line[start..end].to_string())
    };
    // `android.view.View void setVisibility(int) 0` → parts
    let mut item: Option<(String, String, String, usize)> = None;
    let mut cur_ann: Option<String> = None;
    for line in text.lines() {
        let t = line.trim();
        if t.starts_with("<item ") {
            // `android.view.View void setVisibility(int) 0` — class,
            // RETURN type, method(args), parameter index.
            let name = attr(t, "name").unwrap_or_default();
            let mut tail = name.rsplitn(2, ' ');
            let param = tail.next().and_then(|p| p.parse::<usize>().ok());
            let rest = tail.next().unwrap_or("").trim().to_string();
            let (class, rest) = match rest.split_once(' ') {
                Some((c, r)) => (c.replace('.', "/"), r.to_string()),
                None => (rest.clone(), String::new()),
            };
            // `void setVisibility(int)` → method `setVisibility`, dex
            // descriptor `(I)V`.
            let (ret, sig) = match rest.split_once(' ') {
                Some((r, s)) => (r.to_string(), s.to_string()),
                None => (String::new(), rest.clone()),
            };
            let (method, args) = match sig.split_once('(') {
                Some((m, a)) => (m.to_string(), a.trim_end_matches(')')),
                None => (sig.clone(), ""),
            };
            let mut desc = String::from("(");
            for a in args.split(',') {
                desc.push_str(&java_type_to_dex(a.trim()));
            }
            desc.push(')');
            desc.push_str(&java_type_to_dex(&ret));
            item = param.map(|p| (class, method, desc, p));
        } else if t.starts_with("<annotation ") {
            cur_ann = attr(t, "name");
        } else if t.starts_with("<val ") {
            if let (Some((class, method, desc, param)), Some(ann)) = (&item, &cur_ann) {
                if attr(t, "name").as_deref() == Some("value") {
                    if let Some(v) = attr(t, "val") {
                        on_domain(class, method, desc, *param, ann, &v);
                    }
                }
            }
        } else if t.starts_with("</item>") {
            item = None;
            cur_ann = None;
        }
    }
}

// ---------------------------------------------------------------------------
// android.jar classfile constants
// ---------------------------------------------------------------------------

/// Read every static-final field's constant value out of one classfile.
/// Only the pieces a constant lookup needs survive: the constant pool
/// (Utf8/Class/Integer/Long/String entries), field_info with its
/// ConstantValue attribute, and method descriptors for domain keys.
/// (owner, field) → value; (owner, method, descriptor) list.
pub type ClassConstants = (HashMap<(String, String), i64>, Vec<(String, String, String)>);

pub fn classfile_constants(bytes: &[u8]) -> Option<ClassConstants> {
    if bytes.len() < 10 || &bytes[..4] != b"\xca\xfe\xba\xbe" {
        return None;
    }
    let rd_u1 = |p: usize| -> Option<u8> { bytes.get(p).copied() };
    let rd_u2 = |p: usize| -> Option<u16> {
        Some(u16::from_be_bytes([bytes.get(p).copied()?, bytes.get(p + 1).copied()?]))
    };
    let rd_u4 = |p: usize| -> Option<u32> {
        Some(u32::from_be_bytes([
            bytes.get(p).copied()?,
            bytes.get(p + 1).copied()?,
            bytes.get(p + 2).copied()?,
            bytes.get(p + 3).copied()?,
        ]))
    };
    let rd_i64 = |p: usize| -> Option<i64> {
        Some(i64::from_be_bytes([
            bytes.get(p).copied()?,
            bytes.get(p + 1).copied()?,
            bytes.get(p + 2).copied()?,
            bytes.get(p + 3).copied()?,
            bytes.get(p + 4).copied()?,
            bytes.get(p + 5).copied()?,
            bytes.get(p + 6).copied()?,
            bytes.get(p + 7).copied()?,
        ]))
    };

    // ---- constant pool ----
    let count = rd_u2(8)? as usize;
    // slot → (tag, data); longs/doubles occupy two slots.
    let mut tags = vec![0u8; count];
    let mut ints: HashMap<usize, i32> = HashMap::new();
    let mut longs: HashMap<usize, i64> = HashMap::new();
    let mut utf8s: HashMap<usize, (usize, usize)> = HashMap::new(); // (offset, len)
    let mut classes: HashMap<usize, usize> = HashMap::new();        // slot → name idx
    let mut p = 10usize;
    let mut i = 1usize;
    while i < count {
        let tag = rd_u1(p)?;
        p += 1;
        tags[i] = tag;
        match tag {
            1 => {
                let len = rd_u2(p)? as usize;
                utf8s.insert(i, (p + 2, len));
                p += 2 + len;
            }
            3 => {
                ints.insert(i, i32::from_be_bytes(rd_u4(p)?.to_be_bytes()));
                p += 4;
            }
            // Float(4): 4 bytes — grouping it with the u16 tags
            // desynced the whole pool (34/12k classes survived).
            4 => p += 4,
            5 | 6 | 7 | 8 | 16 | 19 | 20 => {
                if tag == 5 {
                    longs.insert(i, rd_i64(p)?);
                }
                if tag == 7 {
                    classes.insert(i, rd_u2(p)? as usize);
                }
                p += if tag == 5 || tag == 6 { 8 } else { 2 };
            }
            9 | 10 | 11 | 12 | 17 | 18 => p += 4,
            15 => p += 3,
            _ => return None, // unknown tag: bail on this class
        }
        // Long/Double occupy TWO pool slots — the phantom must be
        // skipped or every following tag reads as 0 and the pool
        // desyncs.
        i += if tag == 5 || tag == 6 { 2 } else { 1 };
        let _ = i;
    }
    let utf8 = |slot: usize| -> Option<String> {
        let (off, len) = *utf8s.get(&slot)?;
        // java classfiles use MODIFIED UTF-8; the android framework's
        // names are ASCII — lossy decode is faithful for our purpose.
        Some(String::from_utf8_lossy(bytes.get(off..off + len)?).into_owned())
    };
    // ---- access, this, super, interfaces ----
    // (access_flags comes FIRST — reading this_class at p desynced
    // everything downstream by 2 bytes.)
    let this_class = *classes.get(&(rd_u2(p + 2)? as usize))?;
    p += 6;

    // ---- fields + methods ----
    let ifaces = rd_u2(p)? as usize;
    p += 2 + 2 * ifaces;
    let class_name = utf8(this_class)?.trim_start_matches('L').trim_end_matches(';').to_string();

    let mut constants = HashMap::new();
    let mut methods = Vec::new();
    for read_fields in [true, false] {
        let n = rd_u2(p)? as usize;
        p += 2;
        for _ in 0..n {
            let _access = rd_u2(p)?;
            let name_idx = rd_u2(p + 2)? as usize;
            let desc_idx = rd_u2(p + 4)? as usize;
            let nattrs = rd_u2(p + 6)? as usize;
            p += 8;
            let name = utf8(name_idx)?;
            let desc = utf8(desc_idx)?;
            for _ in 0..nattrs {
                let attr_name = utf8(rd_u2(p)? as usize)?;
                let len = rd_u4(p + 2)? as usize;
                let body = p + 6;
                if read_fields && attr_name == "ConstantValue" {
                    let idx = rd_u2(body)? as usize;
                    let value = if let Some(v) = ints.get(&idx) {
                        Some(*v as i64)
                    } else {
                        longs.get(&idx).copied()
                    };
                    if let Some(v) = value {
                        constants.insert((class_name.clone(), name.clone()), v);
                    }
                }
                if !read_fields {
                    methods.push((class_name.clone(), name.clone(), desc.clone()));
                }
                p = body + len;
            }
        }
    }
    Some((constants, methods))
}

#[cfg(test)]
mod tests {
    use super::*;

    const XML: &[u8] = br#"
<root>
  <item name="android.view.View void setVisibility(int) 0">
    <annotation name="androidx.annotation.IntDef">
      <val name="value" val="{android.view.View.VISIBLE, android.view.View.INVISIBLE, android.view.View.GONE}" />
    </annotation>
  </item>
  <item name="android.content.Intent android.content.Intent addFlags(int) 0">
    <annotation name="androidx.annotation.IntDef">
      <val name="value" val="{android.content.Intent.FLAG_ACTIVITY_NEW_TASK, android.content.Intent.FLAG_ACTIVITY_CLEAR_TOP}" />
    </annotation>
  </item>
  <item name="android.view.View void setSomething(android.view.View) 1">
    <annotation name="androidx.annotation.StringDef">
      <val name="value" val="{android.view.View.NAME}" />
    </annotation>
  </item>
</root>
"#;

    #[test]
    fn domains_parse_and_match() {
        let mut constants: HashMap<(String, String), i64> = HashMap::new();
        for (c, f, v) in [
            ("android/view/View", "VISIBLE", 0i64),
            ("android/view/View", "INVISIBLE", 4),
            ("android/view/View", "GONE", 8),
            ("android/content/Intent", "FLAG_ACTIVITY_NEW_TASK", 0x10000000),
            ("android/content/Intent", "FLAG_ACTIVITY_CLEAR_TOP", 0x04000000),
        ] {
            constants.insert((c.to_string(), f.to_string()), v);
        }
        let syms = PlatformSymbols::from_metadata(&[XML], &constants);
        assert_eq!(syms.domain_count(), 2, "IntDef domains only");
        // named_constant reads the process-global registry.
        set_symbols(PlatformSymbols::from_metadata(&[XML], &constants));

        // Exact member values render; off-domain literals stay numeric.
        assert_eq!(
            named_constant("android/view/View", "setVisibility", "(I)V", 0, 8),
            Some("android.view.View.GONE".to_string())
        );
        assert!(named_constant("android/view/View", "setVisibility", "(I)V", 0, 7).is_none());
        // Unknown methods and wrong descriptors stay numeric.
        assert!(named_constant("android/view/View", "setAlpha", "(F)V", 0, 0).is_none());
        assert!(named_constant("android/view/View", "setVisibility", "(J)V", 0, 0).is_none());
    }

    #[test]
    fn classfile_constants_reads_constant_value() {
        // Minimal classfile: Utf8/Class/Utf8/Utf8/Utf8/Integer pool, one
        // field with a ConstantValue attribute.
        let mut entries: Vec<Vec<u8>> = Vec::new();
        entries.push(vec![]); // slot 0 unused
        let add_utf8 = |entries: &mut Vec<Vec<u8>>, s: &str| {
            let mut e = vec![1u8];
            e.extend_from_slice(&(s.len() as u16).to_be_bytes());
            e.extend_from_slice(s.as_bytes());
            entries.push(e);
            entries.len() as u16 - 1
        };
        let class_entry = add_utf8(&mut entries, "View");
        let mut e = vec![7u8];
        e.extend_from_slice(&class_entry.to_be_bytes());
        entries.push(e);
        let class_idx = (entries.len() - 1) as u16;
        let field_name = add_utf8(&mut entries, "GONE");
        let field_desc = add_utf8(&mut entries, "I");
        let attr_name = add_utf8(&mut entries, "ConstantValue");
        let mut e = vec![3u8];
        e.extend_from_slice(&8i32.to_be_bytes());
        entries.push(e);
        let int_idx = (entries.len() - 1) as u16;

        let mut class = Vec::new();
        class.extend_from_slice(b"\xca\xfe\xba\xbe");
        class.extend_from_slice(&0u16.to_be_bytes()); // minor
        class.extend_from_slice(&52u16.to_be_bytes()); // major
        class.extend_from_slice(&(entries.len() as u16).to_be_bytes());
        for e in &entries[1..] {
            class.extend_from_slice(e);
        }
        class.extend_from_slice(&0x0008u16.to_be_bytes()); // access
        class.extend_from_slice(&class_idx.to_be_bytes()); // this
        class.extend_from_slice(&0u16.to_be_bytes()); // super = Object (invalid idx 0 ok)
        class.extend_from_slice(&0u16.to_be_bytes()); // interfaces
        class.extend_from_slice(&1u16.to_be_bytes()); // 1 field
        class.extend_from_slice(&0x0019u16.to_be_bytes()); // field access
        class.extend_from_slice(&field_name.to_be_bytes());
        class.extend_from_slice(&field_desc.to_be_bytes());
        class.extend_from_slice(&1u16.to_be_bytes()); // 1 attribute
        class.extend_from_slice(&attr_name.to_be_bytes());
        class.extend_from_slice(&2u32.to_be_bytes()); // attr len
        class.extend_from_slice(&int_idx.to_be_bytes());
        class.extend_from_slice(&0u16.to_be_bytes()); // methods count

        let (constants, _methods) = classfile_constants(&class).expect("parse");
        assert_eq!(
            constants.get(&("View".to_string(), "GONE".to_string())),
            Some(&8i64),
            "constants: {constants:?}"
        );
    }
}
