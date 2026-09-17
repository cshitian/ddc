//! Cross-reference search over DEX images WITHOUT decompiling: resolve the
//! query against the id tables (strings / types / method_ids / field_ids),
//! then scan every method's decoded instructions for the matching indices.
//! Ascending-C-style "query the artifact as a database" — the pool parse
//! (~0.35s on weibo) is the only fixed cost; the scan is pure decoding,
//! no lifting/structuring/rendering.

use std::collections::HashSet;

use anyhow::Result;
use ddc_dex::insn::InsnKind;
use ddc_dex::DexFile;

/// What the user is looking for.
#[derive(Debug, Clone)]
pub enum FindQuery {
    /// Substring match (case-insensitive) against string literals.
    String(String),
    /// Substring match against type names (`com.poc.Main`,
    /// `com/poc/Main`, `Lcom/poc/Main;` all normalize).
    Type(String),
    Method {
        class: Option<String>,
        name: String,
        fuzzy_class: bool,
    },
    Field {
        class: Option<String>,
        name: String,
        fuzzy_class: bool,
    },
}

impl FindQuery {
    pub fn kind(&self) -> &'static str {
        match self {
            FindQuery::String(_) => "string",
            FindQuery::Type(_) => "type",
            FindQuery::Method { .. } => "method",
            FindQuery::Field { .. } => "field",
        }
    }
}

/// Normalize any of `com.poc.Main`, `com/poc/Main`, `Lcom/poc/Main;` to
/// the internal slashed form `com/poc/Main`.
pub fn normalize_type(q: &str) -> String {
    let mut s = q.trim();
    if let Some(stripped) = s.strip_prefix('L') {
        if s.ends_with(';') {
            s = &stripped[..stripped.len().saturating_sub(1)];
        }
    }
    s.replace('.', "/")
}

fn matches(hay: &str, needle: &str) -> bool {
    hay.to_ascii_lowercase()
        .contains(&needle.to_ascii_lowercase())
}

fn class_matches(type_name: &str, class: &str, fuzzy: bool) -> bool {
    let hay = type_name.trim_start_matches('L').trim_end_matches(';');
    let needle = normalize_type(class);
    if fuzzy {
        matches(hay, &needle)
    } else {
        hay == needle
    }
}

/// One reference hit.
pub struct Hit {
    /// Owner class, slashed internal form.
    pub class: String,
    /// Owner method, `name(descriptor)`.
    pub method: String,
    /// Instruction kind (`const-string`, `new-instance`, `invoke`...).
    pub insn: &'static str,
    /// Rendered target (`"token"`, `Lcom/poc/Main;`, `Lc;->f:I`, `Lc;->m(I)V`).
    pub target: String,
}

/// Scan one dex image for `query`. Returns hits in class/method order.
pub fn scan_dex(_label: &str, dex: &DexFile, query: &FindQuery) -> Result<Vec<Hit>> {
    // 1. Resolve the target index set.
    let string_idx: HashSet<u32> = match query {
        FindQuery::String(pat) => (0..dex.string_count() as u32)
            .filter(|&i| matches(dex.string(i), pat))
            .collect(),
        _ => HashSet::new(),
    };
    let type_idx: HashSet<u32> = match query {
        FindQuery::Type(pat) => {
            let norm = normalize_type(pat);
            (0..dex.type_count() as u32)
                .filter(|&i| {
                    let t = dex.type_name(i);
                    let t = t.trim_start_matches('L').trim_end_matches(';');
                    t.to_ascii_lowercase().contains(&norm.to_ascii_lowercase())
                })
                .collect()
        }
        _ => HashSet::new(),
    };
    let method_idx: HashSet<u32> = match query {
        FindQuery::Method { class, name, fuzzy_class } => {
            let name = name.to_ascii_lowercase();
            (0..dex.method_count() as u32)
                .filter(|&i| {
                    let m = dex.method(i);
                    let mname = dex.string(m.name_idx).to_ascii_lowercase();
                    if !mname.contains(&name) {
                        return false;
                    }
                    match class {
                        Some(c) => class_matches(&dex.class_name(m.class_idx), c, *fuzzy_class),
                        None => true,
                    }
                })
                .collect()
        }
        _ => HashSet::new(),
    };
    let field_idx: HashSet<u32> = match query {
        FindQuery::Field { class, name, fuzzy_class } => {
            let name = name.to_ascii_lowercase();
            (0..dex.field_count() as u32)
                .filter(|&i| {
                    let f = dex.field(i);
                    let fname = dex.string(f.name_idx).to_ascii_lowercase();
                    if !fname.contains(&name) {
                        return false;
                    }
                    match class {
                        Some(c) => class_matches(&dex.class_name(f.class_idx), c, *fuzzy_class),
                        None => true,
                    }
                })
                .collect()
        }
        _ => HashSet::new(),
    };
    if string_idx.is_empty()
        && type_idx.is_empty()
        && method_idx.is_empty()
        && field_idx.is_empty()
    {
        return Ok(Vec::new());
    }

    // 2. Walk every method's decoded instructions.
    let mut hits = Vec::new();
    for cd in &dex.class_defs {
        let class = dex.class_name(cd.class_idx);
        let data = dex.class_data(cd);
        let methods = data.direct_methods.iter().chain(data.virtual_methods.iter());
        for m in methods {
            if m.code_off == 0 {
                continue;
            }
            let Some(code) = dex.code_at(m.code_off) else {
                continue;
            };
            let mid = dex.method(m.method_idx);
            let mname = dex.string(mid.name_idx);
            let desc = render_proto(dex, mid.proto_idx);
            let owner = format!("{mname}{desc}");
            for insn in &code.insns {
                match &insn.kind {
                    InsnKind::ConstString { str_idx, .. } => {
                        if string_idx.contains(str_idx) {
                            hits.push(Hit {
                                class: class.clone(),
                                method: owner.clone(),
                                insn: "const-string",
                                target: format!("{:?}", dex.string(*str_idx)),
                            });
                        }
                    }
                    InsnKind::ConstClass { type_idx: idx, .. }
                    | InsnKind::CheckCast { type_idx: idx, .. }
                    | InsnKind::InstanceOf { type_idx: idx, .. }
                    | InsnKind::NewInstance { type_idx: idx, .. }
                    | InsnKind::NewArray { type_idx: idx, .. }
                    | InsnKind::FilledNewArray { type_idx: idx, .. } => {
                        if type_idx.contains(idx) {
                            hits.push(Hit {
                                class: class.clone(),
                                method: owner.clone(),
                                insn: kind_name(&insn.kind),
                                target: dex.type_name(*idx).to_string(),
                            });
                        }
                    }
                    InsnKind::IGet { field_idx: idx, .. }
                    | InsnKind::IPut { field_idx: idx, .. }
                    | InsnKind::SGet { field_idx: idx, .. }
                    | InsnKind::SPut { field_idx: idx, .. } => {
                        if field_idx.contains(idx) {
                            hits.push(Hit {
                                class: class.clone(),
                                method: owner.clone(),
                                insn: kind_name(&insn.kind),
                                target: render_field(dex, *idx),
                            });
                        }
                    }
                    InsnKind::Invoke { method_idx: idx, .. } => {
                        if method_idx.contains(idx) {
                            hits.push(Hit {
                                class: class.clone(),
                                method: owner.clone(),
                                insn: "invoke",
                                target: render_method(dex, *idx),
                            });
                        }
                    }
                    _ => {}
                }
            }
        }
    }
    Ok(hits)
}

fn kind_name(k: &InsnKind) -> &'static str {
    match k {
        InsnKind::ConstClass { .. } => "const-class",
        InsnKind::CheckCast { .. } => "check-cast",
        InsnKind::InstanceOf { .. } => "instance-of",
        InsnKind::NewInstance { .. } => "new-instance",
        InsnKind::NewArray { .. } => "new-array",
        InsnKind::FilledNewArray { .. } => "filled-new-array",
        InsnKind::IGet { .. } => "iget",
        InsnKind::IPut { .. } => "iput",
        InsnKind::SGet { .. } => "sget",
        InsnKind::SPut { .. } => "sput",
        _ => "ref",
    }
}

fn render_proto(dex: &DexFile, proto_idx: u32) -> String {
    let params: String = dex
        .proto_params(proto_idx)
        .into_iter()
        .map(|t| dex.type_name(t).to_string())
        .collect();
    // dex.proto() returns &ProtoId directly (Option is only on lookup).
    let ret = dex.type_name(dex.proto(proto_idx).return_type_idx).to_string();
    format!("({params}){ret}")
}

fn render_field(dex: &DexFile, idx: u32) -> String {
    let f = dex.field(idx);
    format!(
        "{}->{}:{}",
        dex.class_name(f.class_idx),
        dex.string(f.name_idx),
        dex.type_name(f.type_idx)
    )
}

fn render_method(dex: &DexFile, idx: u32) -> String {
    let m = dex.method(idx);
    let desc = render_proto(dex, m.proto_idx);
    format!(
        "{}->{}{}",
        dex.class_name(m.class_idx),
        dex.string(m.name_idx),
        desc
    )
}
