//! The browse/locate subcommands: strings, members, hierarchy, largest,
//! getmethod, disasm, callers, pkg. All ride the RawDex zero-materialization
//! path (raw images, prefix-friendly), mirroring jadx's quick-lookup tools.

use anyhow::{bail, Context, Result};
use std::path::PathBuf;

use crate::findrefs::{decode_mutf8_lossy, RawDex};
use crate::inputs::{
    collect_images, expand_inputs, filter_images_by_dex, inflate_images, parse_images,
};

/// Parse every image (parallel), handing each (label, image) to `f`.
/// Bounded like the findrefs pipeline; progressive commands never hold all
/// images at peak — they fold each one and drop it.
pub(crate) fn for_each_image(
    input: &PathBuf,
    dex_filters: &[String],
    f: &mut dyn FnMut(&str, &[u8]),
) -> Result<()> {
    let files = expand_inputs(std::slice::from_ref(input))?;
    let images = filter_images_by_dex(collect_images(&files)?, dex_filters)?;
    const WAVE: usize = 8;
    let mut rest = images;
    while !rest.is_empty() {
        let wave = rest.split_off(rest.len().saturating_sub(WAVE));
        for (label, raw) in inflate_images(wave)? {
            f(&label, &raw);
        }
    }
    Ok(())
}

/// Shared argument prelude: input + optional --dex filters. Positionals
/// beyond the first (the input) are surfaced as `rest` — several browse
/// commands take a class/method/package argument after the input.
pub(crate) struct Common {
    pub(crate) input: PathBuf,
    pub(crate) dex_filters: Vec<String>,
    pub(crate) rest: Vec<String>,
}

pub(crate) fn parse_common(args: &[String], cmd: &str) -> Result<Common> {
    let mut positionals: Vec<String> = Vec::new();
    let mut dex_filters: Vec<String> = Vec::new();
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "-d" | "--dex" => {
                dex_filters.push(args.get(i + 1).context("--dex needs a value")?.to_string());
                i += 1;
            }
            a if a.starts_with('-') => bail!("{cmd}: unknown option {a}"),
            a => positionals.push(a.to_string()),
        }
        i += 1;
    }
    let input = positionals
        .first()
        .cloned()
        .context(format!("{cmd} needs an input file"))?;
    Ok(Common {
        input: PathBuf::from(input),
        dex_filters,
        rest: positionals.into_iter().skip(1).collect(),
    })
}

// ---- strings ---------------------------------------------------------------

pub(crate) fn cmd_strings(args: &[String]) -> Result<()> {
    let mut filter: Option<String> = None;
    let mut with_loc = false;
    let mut rest: Vec<String> = Vec::new();
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "-f" | "--filter" => {
                filter = Some(args.get(i + 1).context("--filter needs a value")?.to_string());
                i += 1;
            }
            "--with-locations" => with_loc = true,
            "-d" | "--dex" => {
                // parse_common owns -d/--dex, but this loop runs first —
                // forward both tokens so it can see them.
                rest.push(args[i].clone());
                rest.push(args.get(i + 1).context("--dex needs a value")?.clone());
                i += 1;
            }
            a if a.starts_with('-') => bail!("strings: unknown option {a}"),
            a => rest.push(a.to_string()),
        }
        i += 1;
    }
    let common = parse_common(&rest, "strings")?;

    println!("{:10}  {}", "dex", if with_loc { "string  used-by" } else { "string" });
    for_each_image(&common.input, &common.dex_filters, &mut |label, image| {
        let dex_name = label.rsplit_once('!').map(|(_, e)| e).unwrap_or(label).to_string();
        let Ok(dex) = RawDex::parse(image) else { return };
        // Matching strings (SIMD memmem over raw bytes).
        let needle = filter.as_deref().map(str::as_bytes);
        let matched: std::collections::BTreeMap<u32, ()> = (0..dex.str_n as u32)
            .filter(|&idx| {
                let Some(bytes) = dex.string_bytes(idx) else { return false };
                match needle {
                    Some(f) => bytes.len() >= f.len() && bytes.windows(f.len()).any(|w| w == f),
                    None => true,
                }
            })
            .map(|idx| (idx, ()))
            .collect();
        // Exact usage locations: walk every method's const-string sites.
        let mut users: std::collections::HashMap<u32, Vec<String>> =
            std::collections::HashMap::new();
        if with_loc {
            for ci in 0..dex.cls_n {
                let Some((ty, _, _, cdo, _)) = dex.class_def_parts(ci) else { continue };
                let class = dex.class_name(ty);
                let Some(methods) = dex.methods_of(cdo as usize) else { continue };
                for (midx, _acc, code_off) in methods {
                    if code_off == 0 || code_off as usize + 16 > dex.d.len() {
                        continue;
                    }
                    let insns = u32::from_le_bytes([
                        dex.d[code_off as usize + 12],
                        dex.d[code_off as usize + 13],
                        dex.d[code_off as usize + 14],
                        dex.d[code_off as usize + 15],
                    ]) as usize;
                    let start = code_off as usize + 16;
                    let end = (start + 2 * insns).min(dex.d.len());
                    if start >= end {
                        continue;
                    }
                    let owner = dex
                        .method_parts(midx)
                        .map(|(_, p, nb)| format!("{} {}{}", class, decode_mutf8_lossy(nb), dex.proto_desc(p)))
                        .unwrap_or_default();
                    ddc_dex::insn::scan_instructions(&dex.d[start..end], &mut |op, _pc, bytes| {
                        if op != 0x1a && op != 0x1b {
                            return;
                        }
                        let lo = 2 * (_pc + 1);
                        let idx = if op == 0x1b
                            && lo + 4 <= bytes.len()
                        {
                            u32::from_le_bytes([bytes[lo], bytes[lo + 1], bytes[lo + 2], bytes[lo + 3]])
                        } else if lo + 2 <= bytes.len() {
                            u16::from_le_bytes([bytes[lo], bytes[lo + 1]]) as u32
                        } else {
                            return;
                        };
                        if matched.contains_key(&idx) {
                            users.entry(idx).or_default().push(owner.clone());
                        }
                    });
                }
            }
        }
        for &idx in matched.keys() {
            let s = decode_mutf8_lossy(dex.string_bytes(idx).unwrap_or(&[]));
            match users.get(&idx) {
                Some(u) if !u.is_empty() => {
                    let mut uniq: Vec<&str> = u.iter().map(|m| m.as_str()).collect();
                    uniq.dedup();
                    println!("{:10}  {:?}  {}", dex_name, s, uniq.join("; "))
                }
                _ => println!("{:10}  {:?}", dex_name, s),
            }
        }
    })
}

// ---- members ---------------------------------------------------------------

pub(crate) fn cmd_members(args: &[String]) -> Result<()> {
    let mut rest: Vec<String> = Vec::new();
    let mut class: Option<String> = None;
    let mut fuzzy_class = false;
    let mut kind_want: Option<&str> = None; // method | field
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--class" | "-C" => {
                class = Some(args.get(i + 1).context("--class needs a value")?.to_string());
                i += 1;
            }
            "--fuzzy-class" => fuzzy_class = true,
            "--method" | "--field" => kind_want = Some(args[i].trim_start_matches('-')),
            "-d" | "--dex" => {
                // parse_common owns -d/--dex, but this loop runs first —
                // forward both tokens so it can see them.
                rest.push(args[i].clone());
                rest.push(args.get(i + 1).context("--dex needs a value")?.clone());
                i += 1;
            }
            a if a.starts_with('-') => bail!("members: unknown option {a}"),
            a => rest.push(a.to_string()),
        }
        i += 1;
    }
    let common = parse_common(&rest, "members")?;
    let name = common.rest.first().cloned();

    println!("{:10}  {:<6}  {}", "dex", "kind", "class member");
    for_each_image(&common.input, &common.dex_filters, &mut |label, image| {
        let dex_name = label.rsplit_once('!').map(|(_, e)| e).unwrap_or(label).to_string();
        let Ok(dex) = RawDex::parse(image) else { return };
        let class_ok = |cb: &[u8]| -> bool {
            match &class {
                None => true,
                Some(c) => {
                    let hay = String::from_utf8_lossy(cb);
                    let hay = hay.trim_start_matches('L').trim_end_matches(';');
                    let needle = c.replace('.', "/");
                    if fuzzy_class { hay.contains(&needle) } else { hay == needle }
                }
            }
        };
        if kind_want != Some("field") {
            for mi in 0..dex.method_n as u32 {
                let Some((cidx, proto, nb)) = dex.method_parts(mi) else { continue };
                if let Some(n) = name.as_deref() {
                    if !dex_match(nb, n.as_bytes()) {
                        continue;
                    }
                }
                if let Some(cb) = dex.type_bytes(cidx) {
                    if !class_ok(cb) { continue; }
                    println!("{:10}  {:<6}  {} {}{}", dex_name, "method",
                        dex.class_name(cidx), decode_mutf8_lossy(nb), dex.proto_desc(proto));
                }
            }
        }
        if kind_want != Some("method") {
            for fi in 0..dex.field_n as u32 {
                let Some((cidx, nb, tb)) = dex.field_parts(fi) else { continue };
                if let Some(n) = name.as_deref() {
                    if !dex_match(nb, n.as_bytes()) { continue; }
                }
                if let Some(cb) = dex.type_bytes(cidx) {
                    if !class_ok(cb) { continue; }
                    println!("{:10}  {:<6}  {} {} {}", dex_name, "field",
                        dex.class_name(cidx), decode_mutf8_lossy(nb), decode_mutf8_lossy(tb));
                }
            }
        }
    })
}

/// Case-sensitive substring match on raw MUTF-8 bytes (None needle = all).
fn dex_match(nb: &[u8], needle: &[u8]) -> bool {
    nb.len() >= needle.len() && nb.windows(needle.len()).any(|w| w == needle)
}

// ---- hierarchy ---------------------------------------------------------------

pub(crate) fn cmd_hierarchy(args: &[String]) -> Result<()> {
    let mut rest: Vec<String> = Vec::new();
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "-d" | "--dex" => {
                // parse_common owns -d/--dex, but this loop runs first —
                // forward both tokens so it can see them.
                rest.push(args[i].clone());
                rest.push(args.get(i + 1).context("--dex needs a value")?.clone());
                i += 1;
            }
            a if a.starts_with('-') => bail!("hierarchy: unknown option {a}"),
            a => rest.push(a.to_string()),
        }
        i += 1;
    }
    let common = parse_common(&rest, "hierarchy")?;
    let target = common
        .rest
        .first()
        .context("hierarchy needs a class name")?
        .replace('.', "/");

    println!("{:10}  {:<9}  {}", "dex", "relation", "class");
    // Map: super/interface type idx -> child classes (per image).
    for_each_image(&common.input, &common.dex_filters, &mut |label, image| {
        let dex_name = label.rsplit_once('!').map(|(_, e)| e).unwrap_or(label).to_string();
        let Ok(dex) = RawDex::parse(image) else { return };
        // Resolve the target's type idx in THIS image (name → idx).
        let mut target_idx: Option<u32> = None;
        for ti in 0..dex.type_n as u32 {
            if let Some(b) = dex.type_bytes(ti) {
                let n = decode_mutf8_lossy(b);
                let plain = n.trim_start_matches('L').trim_end_matches(';');
                if plain == target {
                    target_idx = Some(ti);
                    break;
                }
            }
        }
        // Build the child map for whichever relation names we hit.
        for ci in 0..dex.cls_n {
            let Some((ty, sup, iface_off, _, _)) = dex.class_def_parts(ci) else { continue };
            let self_name = dex.class_name(ty);
            if target_idx.is_some() && ty == target_idx.unwrap() {
                // print self + lineage up
                println!("{:10}  {:<9}  {}", dex_name, "class", self_name);
                if sup != u32::MAX {
                    if let Some(sb) = dex.type_bytes(sup) {
                        println!("{:10}  {:<9}  {}", dex_name, "extends", decode_mutf8_lossy(sb));
                    }
                }
                for it in dex.interface_types(iface_off) {
                    if let Some(ib) = dex.type_bytes(it) {
                        println!("{:10}  {:<9}  {}", dex_name, "implements", decode_mutf8_lossy(ib));
                    }
                }
            }
            if sup != u32::MAX && sup == target_idx.unwrap_or(u32::MAX) {
                println!("{:10}  {:<9}  {}", dex_name, "sub", self_name);
            }
            for it in dex.interface_types(iface_off) {
                if it == target_idx.unwrap_or(u32::MAX) {
                    println!("{:10}  {:<9}  {}", dex_name, "impl", self_name);
                }
            }
            // target not present as a type in this image: match by name
            // (hierarchy across images where the parent lives elsewhere).
            if target_idx.is_none() {
                if sup != u32::MAX {
                    if let Some(sb) = dex.type_bytes(sup) {
                        if plain_of(&decode_mutf8_lossy(sb)) == target {
                            println!("{:10}  {:<9}  {}", dex_name, "sub", self_name);
                        }
                    }
                }
                for it in dex.interface_types(iface_off) {
                    if let Some(ib) = dex.type_bytes(it) {
                        if plain_of(&decode_mutf8_lossy(ib)) == target {
                            println!("{:10}  {:<9}  {}", dex_name, "impl", self_name);
                        }
                    }
                }
                if plain_of(&self_name) == target {
                    println!("{:10}  {:<9}  {}", dex_name, "class", self_name);
                }
            }
        }
    })
}

fn plain_of(desc: &str) -> &str {
    desc.trim_start_matches('L').trim_end_matches(';')
}

// ---- largest ---------------------------------------------------------------

pub(crate) fn cmd_largest(args: &[String]) -> Result<()> {
    let mut limit = 20usize;
    let mut rest: Vec<String> = Vec::new();
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "-n" => {
                limit = args.get(i + 1).context("-n needs a count")?.parse().unwrap_or(20);
                i += 1;
            }
            "-d" | "--dex" => {
                // parse_common owns -d/--dex, but this loop runs first —
                // forward both tokens so it can see them.
                rest.push(args[i].clone());
                rest.push(args.get(i + 1).context("--dex needs a value")?.clone());
                i += 1;
            }
            a if a.starts_with('-') => bail!("largest: unknown option {a}"),
            a => rest.push(a.to_string()),
        }
        i += 1;
    }
    let common = parse_common(&rest, "largest")?;

    struct Row {
        insns: usize,
        dex: String,
        class: String,
        method: String,
    }
    let mut rows: Vec<Row> = Vec::new();
    for_each_image(&common.input, &common.dex_filters, &mut |label, image| {
        let dex_name = label.rsplit_once('!').map(|(_, e)| e).unwrap_or(label).to_string();
        let Ok(dex) = RawDex::parse(image) else { return };
        for ci in 0..dex.cls_n {
            let Some((ty, _, _, cdo, _)) = dex.class_def_parts(ci) else { continue };
            let class = dex.class_name(ty);
            let Some(methods) = dex.methods_of(cdo as usize) else { continue };
            for (midx, _acc, code_off) in methods {
                if code_off == 0 || code_off as usize + 16 > dex.d.len() {
                    continue;
                }
                let insns = u32::from_le_bytes([
                    dex.d[code_off as usize + 12],
                    dex.d[code_off as usize + 13],
                    dex.d[code_off as usize + 14],
                    dex.d[code_off as usize + 15],
                ]) as usize;
                let method = dex
                    .method_parts(midx)
                    .map(|(_, p, nb)| format!("{}{}", decode_mutf8_lossy(nb), dex.proto_desc(p)))
                    .unwrap_or_default();
                rows.push(Row { insns, dex: dex_name.clone(), class: class.clone(), method });
            }
        }
    });
    rows.sort_by(|a, b| b.insns.cmp(&a.insns));
    println!("{:>7}  {:<10}  {}", "insns", "dex", "class method");
    for r in rows.into_iter().take(limit) {
        println!("{:>7}  {:<10}  {} {}", r.insns, r.dex, r.class, r.method);
    }
    Ok(())
}

// ---- disasm ---------------------------------------------------------------

pub(crate) fn cmd_disasm(args: &[String]) -> Result<()> {
    let mut rest: Vec<String> = Vec::new();
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "-d" | "--dex" => {
                // parse_common owns -d/--dex, but this loop runs first —
                // forward both tokens so it can see them.
                rest.push(args[i].clone());
                rest.push(args.get(i + 1).context("--dex needs a value")?.clone());
                i += 1;
            }
            a if a.starts_with('-') => bail!("disasm: unknown option {a}"),
            a => rest.push(a.to_string()),
        }
        i += 1;
    }
    let common = parse_common(&rest, "disasm")?;
    let target = common
        .rest
        .first()
        .context("disasm needs a class name (optionally Class.method)")?;
    let class_full = target.replace('.', "/");
    // `Cells.t1` (whole thing is a class) vs `Greeter.greet` (class + method):
    // try the whole string as a class first, then fall back to splitting at
    // the last dot.
    let split = target
        .rsplit_once('.')
        .filter(|(c, m)| !c.is_empty() && !m.is_empty() && !m.contains('('))
        .map(|(c, m)| (c.replace('.', "/"), m.to_string()));

    for_each_image(&common.input, &common.dex_filters, &mut |label, image| {
        let Ok(dex) = RawDex::parse(image) else { return };
        let (ci, method_want) = match dex.find_class(&class_full) {
            Some(ci) => (ci, None),
            None => {
                let Some((c, m)) = &split else { return };
                match dex.find_class(c) {
                    Some(ci) => (ci, Some(m.clone())),
                    None => return,
                }
            }
        };
        let (ty, _, _, cdo, _) = dex.class_def_parts(ci).unwrap();
        println!("// {} {}", label, dex.class_name(ty));
        let Some(methods) = dex.methods_of(cdo as usize) else { return };
        for (midx, _acc, code_off) in methods {
            if code_off == 0 {
                continue;
            }
            let owner = dex
                .method_parts(midx)
                .map(|(_, p, nb)| format!("{}{}", decode_mutf8_lossy(nb), dex.proto_desc(p)))
                .unwrap_or_default();
            if let Some(w) = &method_want {
                if !owner.starts_with(w.as_str()) {
                    continue;
                }
            }
            println!("  {}:", owner);
            if code_off as usize + 16 > dex.d.len() {
                continue;
            }
            let insns = u32::from_le_bytes([
                dex.d[code_off as usize + 12],
                dex.d[code_off as usize + 13],
                dex.d[code_off as usize + 14],
                dex.d[code_off as usize + 15],
            ]) as usize;
            let start = code_off as usize + 16;
            let end = (start + 2 * insns).min(dex.d.len());
            ddc_dex::insn::scan_instructions(&dex.d[start..end], &mut |op, pc, _b| {
                println!("    {:04x}  {:02x}  {}", 2 * pc, op, ddc_dex::insn::op_name(op));
            });
        }
    })
}

// ---- callers ---------------------------------------------------------------

pub(crate) fn cmd_callers(args: &[String]) -> Result<()> {
    let mut rest: Vec<String> = Vec::new();
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "-d" | "--dex" => {
                // parse_common owns -d/--dex, but this loop runs first —
                // forward both tokens so it can see them.
                rest.push(args[i].clone());
                rest.push(args.get(i + 1).context("--dex needs a value")?.clone());
                i += 1;
            }
            a if a.starts_with('-') => bail!("callers: unknown option {a}"),
            a => rest.push(a.to_string()),
        }
        i += 1;
    }
    let common = parse_common(&rest, "callers")?;
    // Reuse findrefs method machinery: callers of M = findrefs --kind method
    // name M (optionally scoped to one class).
    let target = common
        .rest
        .first()
        .context("callers needs a method name [class]")?;
    let (name, class) = match common.rest.get(1) {
        Some(c) => (target.clone(), Some(c.clone())),
        None => (target.clone(), None),
    };
    let mut fwd: Vec<String> = vec![
        common.input.display().to_string(),
        "method".into(),
    ];
    if let Some(c) = class {
        fwd.push("--class".into());
        fwd.push(c);
    }
    fwd.push(name);
    crate::cmd_findrefs(&fwd, std::time::Instant::now())
}

// ---- pkg (package subtree decompile) ----------------------------------------

pub(crate) fn cmd_pkg(args: &[String]) -> Result<()> {
    let mut rest: Vec<String> = Vec::new();
    let mut out_dir: Option<PathBuf> = None;
    let mut threads = std::thread::available_parallelism().map(|n| n.get()).unwrap_or(4);
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "-o" | "--output" => {
                out_dir = Some(PathBuf::from(args.get(i + 1).context("-o needs a value")?));
                i += 1;
            }
            "-t" | "--threads" => {
                threads = args.get(i + 1).context("-t needs a count")?.parse().unwrap_or(4);
                i += 1;
            }
            "-d" | "--dex" => {
                // parse_common owns -d/--dex, but this loop runs first —
                // forward both tokens so it can see them.
                rest.push(args[i].clone());
                rest.push(args.get(i + 1).context("--dex needs a value")?.clone());
                i += 1;
            }
            a if a.starts_with('-') => bail!("pkg: unknown option {a}"),
            a => rest.push(a.to_string()),
        }
        i += 1;
    }
    let common = parse_common(&rest, "pkg")?;
    let package = common
        .rest
        .first()
        .context("pkg needs a package name (com.example.foo)")?;
    let out = out_dir.unwrap_or_else(|| {
        common
            .input
            .parent()
            .unwrap_or(std::path::Path::new("."))
            .join(format!("{}-pkg", package.replace('.', "_")))
    });
    std::fs::create_dir_all(&out)?;

    // Names from every image (class_defs only, prefix-friendly).
    // "" / "." = the root: every class (default package included).
    let mut names: Vec<String> = Vec::new();
    let pkg_prefix = if package.is_empty() || package == "." {
        String::new()
    } else {
        format!("{}/", package.replace('.', "/"))
    };
    for_each_image(&common.input, &common.dex_filters, &mut |label, image| {
        let Ok(dex) = RawDex::parse(image) else { return };
        for ci in 0..dex.cls_n {
            let Some((ty, _, _, _, _)) = dex.class_def_parts(ci) else { continue };
            let name = dex.class_name(ty);
            if name.starts_with(&pkg_prefix) {
                let _ = label;
                names.push(name);
            }
        }
    })?;
    if names.is_empty() {
        bail!("no classes under package {package}");
    }

    // Decompile those names through the full pipeline: build the pool with
    // ONLY those classes selected (reuse -c machinery via target list).
    let files = expand_inputs(std::slice::from_ref(&common.input))?;
    let parsed = parse_images(filter_images_by_dex(
        collect_images(&files)?,
        &common.dex_filters,
    )?)?;
    let mut pool = crate::DexPool::new();
    for (label, dex) in parsed {
        let idx = pool.add_dex_lazy(dex);
        pool.set_dex_label(idx, label);
    }
    let pool = std::sync::Arc::new(pool);
    let selected: Vec<String> = names
        .iter()
        .filter(|n| pool.get(n).is_some())
        .cloned()
        .collect();
    eprintln!("ddc: {} class(es) under {package}", selected.len());

    let dirs: std::sync::Mutex<std::collections::HashSet<std::path::PathBuf>> =
        std::sync::Mutex::new(std::collections::HashSet::new());
    let written = std::sync::atomic::AtomicUsize::new(0);
    let queue: Vec<Vec<String>> = selected.chunks(32).map(|c| c.to_vec()).collect();
    let cursor = crate::AtomicUsize::new(0);
    let pending: std::sync::Mutex<
        Vec<(
            std::sync::mpsc::Receiver<Result<String, String>>,
            String,
            std::time::Instant,
        )>,
    > = std::sync::Mutex::new(Vec::new());
    std::thread::scope(|scope| {
        let mut handles = Vec::new();
        let queue_ref = &queue;
        let cursor_ref = &cursor;
        let pool_ref = &pool;
        let out_ref = &out;
        let dirs_ref = &dirs;
        let written_ref = &written;
        let pending_ref = &pending;
        let n = threads.min(queue.len()).max(1);
        for _ in 0..n {
            handles.push(
                std::thread::Builder::new()
                    .stack_size(64 * 1024 * 1024)
                    .spawn_scoped(scope, move || {
                        loop {
                            let qi = cursor_ref.fetch_add(1, crate::Ordering::Relaxed);
                            let Some(chunk) = queue_ref.get(qi) else { break };
                            for name in chunk {
                                let Some(pc) = pool_ref.get(name) else { continue };
                                let res = std::panic::catch_unwind(
                                    std::panic::AssertUnwindSafe(|| {
                                        ddc_dec::classdec::decompile_class(
                                            pool_ref, pc, &crate::ClassOptions::default(), pending_ref,
                                        )
                                    }),
                                );
                                match res {
                                    Ok(Ok(text)) => {
                                        let path = crate::source_path(out_ref, name);
                                        if let Some(parent) = path.parent() {
                                            if dirs_ref.lock().unwrap().insert(parent.to_path_buf()) {
                                                let _ = std::fs::create_dir_all(parent);
                                            }
                                        }
                                        let _ = std::fs::write(&path, text);
                                        written_ref.fetch_add(1, crate::Ordering::Relaxed);
                                    }
                                    Ok(Err(e)) => eprintln!("[!] {}: {e:#}", name.replace('/', ".")),
                                    Err(_) => eprintln!("[!] {}: panic", name.replace('/', ".")),
                                }
                            }
                        }
                    }),
            );
        }
        for h in handles.into_iter().flatten() {
            let _ = h.join();
        }
    });
    eprintln!(
        "ddc: wrote {} file(s) to {}",
        written.load(crate::Ordering::Relaxed),
        out.display()
    );
    Ok(())
}

// ---- getmethod ----------------------------------------------------------------

pub(crate) fn cmd_getmethod(args: &[String]) -> Result<()> {
    let mut rest: Vec<String> = Vec::new();
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "-d" | "--dex" => {
                // parse_common owns -d/--dex, but this loop runs first —
                // forward both tokens so it can see them.
                rest.push(args[i].clone());
                rest.push(args.get(i + 1).context("--dex needs a value")?.clone());
                i += 1;
            }
            a if a.starts_with('-') => bail!("getmethod: unknown option {a}"),
            a => rest.push(a.to_string()),
        }
        i += 1;
    }
    let common = parse_common(&rest, "getmethod")?;
    let target = common
        .rest
        .first()
        .context("getmethod needs a Class.method target")?;
    // Method-granular output rides the class pipeline today: resolve the
    // CLASS and emit it (the class file contains the method). `Class.method`
    // is the documented form, but a bare class name whose last segment looks
    // like an identifier must still resolve — try the split class first,
    // then the whole string.
    let candidates: Vec<String> = match target.rsplit_once('.') {
        Some((c, _m)) => vec![c.to_string(), target.to_string()],
        None => vec![target.to_string()],
    };
    let mut last_err = None;
    for class in candidates {
        let fwd: Vec<String> = vec![common.input.display().to_string(), class];
        match crate::cmd_getclass(&fwd, std::time::Instant::now()) {
            Ok(()) => return Ok(()),
            Err(e) => last_err = Some(e),
        }
    }
    Err(last_err.unwrap_or_else(|| anyhow::anyhow!("getmethod: class not found")))
}
