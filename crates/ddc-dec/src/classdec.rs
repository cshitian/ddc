//! Class-level rendering: header, fields (with static initializers),
//! constructors, methods and nested member classes.

use jdc_core::emit::{escape_string, format_float, Printer};
use jdc_core::types::JavaType;
use jdc_core::Ctx;

use crate::access::*;
use crate::ctx::{java_type_to_generic, DexCtx};
use crate::method::decompile_method;
use crate::{desc_type, DexPool, PoolClass, PoolMethod, StaticValue};

#[derive(Debug, Clone)]
pub struct ClassOptions {
    /// Prefix each file with a provenance comment.
    pub provenance: bool,
}

impl Default for ClassOptions {
    fn default() -> Self {
        ClassOptions { provenance: true }
    }
}

/// Decompile one class (plus nested member classes) to a Java source file.
///
/// Classes with large method bodies run in a monitored thread with a
/// deadline: pathological CFGs can drive the shared structurer's walk into
/// an exponential exploration that never returns. On timeout the class is
/// reported failed and the thread is abandoned (reaped at process exit).
pub fn decompile_class(
    pool: &std::sync::Arc<DexPool>,
    class: &PoolClass,
    opts: &ClassOptions,
    pending: &std::sync::Mutex<
        Vec<(
            std::sync::mpsc::Receiver<Result<String, String>>,
            String,
            std::time::Instant,
        )>,
    >,
) -> anyhow::Result<String> {
    if class_is_risky(pool, class) {
        // Detached monitored thread: the CALLER registers the receiver and
        // moves on (awaiting happens at the end of the run) — a spinning
        // pathological method no longer stalls its worker.
        let pool2 = pool.clone();
        let cls = class.clone();
        let opts2 = opts.clone();
        let (tx, rx) = std::sync::mpsc::channel::<Result<String, String>>();
        let name = class.name.clone();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        let _ = std::thread::Builder::new()
            .stack_size(64 * 1024 * 1024)
            .spawn(move || {
                let r = decompile_class_impl(&pool2, &cls, &opts2).map_err(|e| format!("{:#}", e));
                let _ = tx.send(r);
            });
        pending.lock().unwrap().push((rx, name, deadline));
        return Err(anyhow::anyhow!(
            "deferred to monitored thread (pathological-CFG guard)"
        ));
    }
    decompile_class_impl(pool, class, opts)
}

/// Any method in the exponential-walk danger zone → run under the
/// deadline. Calibrated between real workloads: routine R8 classes top out
/// near 11k insns (reqable's biggest `<clinit>`); the exponential hangs
/// (weibo's gson TypeAdapters) sit at 24k+.
fn class_is_risky(pool: &DexPool, class: &PoolClass) -> bool {
    // Header peek only — decoding every body here would double the APK's
    // total decode work.
    for m in class.all_methods() {
        if m.code_off == 0 {
            continue;
        }
        if let Some(dex) = pool.dex(m.dex_idx) {
            if let Some((_regs, insns)) = dex.code_stats(m.code_off) {
                if insns > 16_000 {
                    return true;
                }
            }
        }
    }
    false
}

fn decompile_class_impl(
    pool: &DexPool,
    class: &PoolClass,
    opts: &ClassOptions,
) -> anyhow::Result<String> {
    let ctx = DexCtx::new(pool, class);
    let mut out = String::new();
    if opts.provenance {
        out.push_str(&format!(
            "// Decompiled by https://github.com/ejfkdev/ddc {}\n",
            env!("CARGO_PKG_VERSION")
        ));
        // Provenance: which input image this class was lifted from (jadx's
        // `loaded from: classes.dex` pattern). Byte-stable across runs —
        // deliberately NO timestamp so outputs diff cleanly.
        let label = pool
            .dex_labels
            .get(class.dex_idx)
            .cloned()
            .unwrap_or_default();
        if let Some(dex) = pool.dex(class.dex_idx) {
            out.push_str(&format!("// From: {} (DEX {})\n", label, dex.version));
        }
    }
    if let Some(src) = &class.source_file {
        out.push_str(&format!("// Source file: {}\n", src));
    }
    if class.is_synthetic() {
        out.push_str("// synthetic\n");
    }
    let (pkg, _) = split_name(&class.name);
    if !pkg.is_empty() {
        out.push('\n');
        out.push_str(&format!("package {};\n", pkg.replace('/', ".")));
    }
    out.push('\n');
    let mut body = String::new();
    emit_class_body(pool, class, &ctx, opts, &mut body, 0)?;
    out.push_str(&body);
    Ok(out)
}

/// Render the class header, fields, methods and nested member classes into
/// `out` (used at top level and recursively for nested members).
fn emit_class_body(
    pool: &DexPool,
    class: &PoolClass,
    ctx: &DexCtx<'_>,
    opts: &ClassOptions,
    out: &mut String,
    depth: usize,
) -> anyhow::Result<()> {
    let ind = indent(depth);
    let (_, simple) = split_name(&class.name);
    let simple = simple.replace('$', ".");
    let is_iface = class.is_interface();
    let is_enum = class.is_enum();

    let mut head = String::new();
    let a = class.access;
    if a & ACC_PUBLIC != 0 {
        head.push_str("public ");
    }
    if a & ACC_FINAL != 0 && !is_enum {
        head.push_str("final ");
    }
    if a & ACC_ABSTRACT != 0 && !is_iface {
        head.push_str("abstract ");
    }
    if a & ACC_ANNOTATION != 0 {
        head.push_str("@");
    }
    if is_enum {
        head.push_str("/* enum */ final class ");
        head.push_str(&simple);
    } else if is_iface {
        head.push_str("interface ");
        head.push_str(&simple);
    } else {
        head.push_str("class ");
        head.push_str(&simple);
    }
    if is_iface {
        if !class.interfaces.is_empty() {
            head.push_str(" extends ");
            head.push_str(&join_dotted(&class.interfaces));
        }
    } else {
        if let Some(sup) = &class.super_name {
            if sup != "java/lang/Object" && !is_enum {
                head.push_str(" extends ");
                head.push_str(&dotted(sup));
            }
        }
        if !class.interfaces.is_empty() {
            head.push_str(if is_iface {
                " extends "
            } else {
                " implements "
            });
            head.push_str(&join_dotted(&class.interfaces));
        }
    }

    out.push_str(&ind);
    out.push_str(&head);
    out.push_str(" {\n");

    // Fields.
    for (i, f) in class.static_fields.iter().enumerate() {
        if i > 0 || !class.instance_fields.is_empty() {
            out.push('\n');
        }
        emit_field(
            pool,
            f,
            class.static_values.get(i),
            &class.name,
            out,
            depth + 1,
            true,
        );
    }
    if !class.instance_fields.is_empty() && !class.static_fields.is_empty() {
        out.push('\n');
    }
    for (i, f) in class.instance_fields.iter().enumerate() {
        if i > 0 {
            out.push('\n');
        }
        emit_field(pool, f, None, &class.name, out, depth + 1, false);
    }

    // Methods.
    let mut emitted_any = !class.static_fields.is_empty() || !class.instance_fields.is_empty();
    for m in class.all_methods() {
        if m.name == "<clinit>" {
            continue; // rendered after the fields
        }
        let text = emit_method(pool, class, ctx, m, depth + 1)?;
        if let Some(text) = text {
            if emitted_any {
                out.push('\n');
            }
            out.push_str(&text);
            emitted_any = true;
        }
    }
    // Static initializer.
    if let Some(clinit) = class.all_methods().find(|m| m.name == "<clinit>") {
        if let Some(text) = emit_method(pool, class, ctx, clinit, depth + 1)? {
            if emitted_any {
                out.push('\n');
            }
            out.push_str(&text);
            emitted_any = true;
        }
    }

    // Nested member classes (clean `$` tails only; anonymous/local/lambda
    // classes are emitted as their own top-level files by the driver).
    for nested in nested_members(pool, class, ctx) {
        if emitted_any {
            out.push('\n');
        }
        let nested_ctx = DexCtx::new(pool, nested);
        out.push('\n');
        emit_class_body(pool, nested, &nested_ctx, opts, out, depth + 1)?;
        emitted_any = true;
    }

    out.push_str(&ind);
    out.push_str("}\n");
    Ok(())
}

/// Member classes of `class` (direct children by the `$` chain / member
/// annotations), excluding anonymous / local / lambda shapes.
fn nested_members<'a>(
    pool: &'a DexPool,
    class: &'a PoolClass,
    ctx: &DexCtx<'_>,
) -> Vec<&'a PoolClass> {
    let mut out = Vec::new();
    for name in pool.children_of(&class.name) {
        let Some(pc) = pool.get(&name) else { continue };
        let rest = &name[class.name.len() + 1..];
        if rest.is_empty() || rest.starts_with('-') {
            continue;
        }
        if ctx.find_outer(&name).as_deref() != Some(class.name.as_str()) {
            continue;
        }
        let tail = rest.rsplit('$').next().unwrap_or(rest);
        if !tail.is_empty() && tail.chars().all(|c| c.is_ascii_digit()) {
            continue; // anonymous
        }
        if tail.starts_with(|c: char| c.is_ascii_digit()) {
            continue; // local
        }
        out.push(pc);
    }
    out
}

fn emit_field(
    pool: &DexPool,
    f: &crate::PoolField,
    init: Option<&StaticValue>,
    f_class: &str,
    out: &mut String,
    depth: usize,
    is_static: bool,
) {
    let ind = indent(depth);
    let mut line = String::new();
    let a = f.access;
    if a & ACC_PUBLIC != 0 {
        line.push_str("public ");
    } else if a & ACC_PRIVATE != 0 {
        line.push_str("private ");
    } else if a & ACC_PROTECTED != 0 {
        line.push_str("protected ");
    }
    if is_static {
        line.push_str("static ");
    }
    if a & ACC_FINAL != 0 {
        line.push_str("final ");
    }
    if a & ACC_SYNTHETIC != 0 {
        line.push_str("/* synthetic */ ");
    }
    if a & ACC_TRANSIENT_HINT != 0 {
        line.push_str("transient ");
    }
    if a & ACC_VOLATILE_HINT != 0 {
        line.push_str("volatile ");
    }
    let ty = type_name(pool, &desc_type(&f.desc));
    line.push_str(&ty);
    line.push(' ');
    line.push_str(&f.name);
    if let Some(v) = init {
        if let Some(text) = render_static_value(v, &f_class) {
            line.push_str(" = ");
            line.push_str(&text);
        }
    }
    line.push(';');
    out.push_str(&ind);
    out.push_str(&line);
    out.push('\n');
}

// DEX field access_flags bits 0x40/0x80 are bridge/varargs for METHODS and
// volatile(0x40)/transient(0x80) for fields.
pub const ACC_VOLATILE_HINT: u32 = 0x40;
pub const ACC_TRANSIENT_HINT: u32 = 0x80;

fn render_static_value(v: &StaticValue, owner: &str) -> Option<String> {
    Some(match v {
        StaticValue::Int(i) => i.to_string(),
        StaticValue::Float(f) => format_float(*f as f64, true),
        StaticValue::Double(d) => format_float(*d, false),
        StaticValue::Str(s) => format!("\"{}\"", escape_string(s)),
        StaticValue::Type(t) => format!("{}.class", dotted(t)),
        StaticValue::Boolean(b) => b.to_string(),
        StaticValue::Null => "null".into(),
        StaticValue::Field(cls, name) => {
            if cls == owner {
                name.clone()
            } else {
                format!("{}.{}", dotted(cls), name)
            }
        }
        StaticValue::Other => return None,
    })
}

fn emit_method(
    pool: &DexPool,
    class: &PoolClass,
    ctx: &DexCtx<'_>,
    m: &PoolMethod,
    depth: usize,
) -> anyhow::Result<Option<String>> {
    let ind = indent(depth);
    let desc = m.parsed_desc();

    // Signature.
    let mut sig = String::new();
    let a = m.access;
    if a & ACC_PUBLIC != 0 {
        sig.push_str("public ");
    } else if a & ACC_PRIVATE != 0 {
        sig.push_str("private ");
    } else if a & ACC_PROTECTED != 0 {
        sig.push_str("protected ");
    }
    let is_clinit = m.name == "<clinit>";
    let is_init = m.name == "<init>";
    if a & ACC_STATIC != 0 || is_clinit {
        sig.push_str("static ");
    }
    if a & ACC_FINAL != 0 {
        sig.push_str("final ");
    }
    if a & (ACC_SYNCHRONIZED | ACC_DECLARED_SYNCHRONIZED) != 0 {
        sig.push_str("synchronized ");
    }
    if a & ACC_NATIVE != 0 {
        sig.push_str("native ");
    }
    if a & ACC_ABSTRACT != 0 {
        sig.push_str("abstract ");
    }
    if a & ACC_SYNTHETIC != 0 {
        sig.push_str("/* synthetic */ ");
    }

    // Body (needed for parameter names even for abstract methods).
    let body = decompile_method(pool, class, m).ok().flatten();
    let param_names: Vec<String> = body
        .as_ref()
        .map(|b| {
            let mut ps: Vec<(u16, String)> =
                b.vt.vars
                    .iter()
                    .filter(|v| v.is_param && v.name != "this")
                    .map(|v| (v.slot, v.name.clone()))
                    .collect();
            ps.sort_by_key(|(s, _)| *s);
            ps.into_iter().map(|(_, n)| n).collect()
        })
        .unwrap_or_else(|| {
            (0..desc.as_ref().map(|d| d.args.len()).unwrap_or(0))
                .map(|i| format!("p{}", i + 1))
                .collect()
        });

    if is_clinit {
        // `static { ... }` — the caller strips the method name/params.
    } else {
        let Some(d) = &desc else { return Ok(None) };
        if is_init {
            let (_, simple) = split_name(&class.name);
            sig.push_str(&simple.replace('$', "."));
        } else {
            sig.push_str(&type_name(pool, &d.ret));
            sig.push(' ');
            sig.push_str(&m.name);
        }
        sig.push('(');
        let n = d.args.len();
        let varargs = a & ACC_VARARGS != 0 && n > 0;
        for (i, arg) in d.args.iter().enumerate() {
            if i > 0 {
                sig.push_str(", ");
            }
            let name = param_names
                .get(i)
                .cloned()
                .unwrap_or_else(|| format!("p{}", i));
            if varargs && i + 1 == n {
                if let JavaType::Array(inner) = arg {
                    sig.push_str(&type_name(pool, inner));
                    sig.push_str("...");
                } else {
                    sig.push_str(&type_name(pool, arg));
                }
            } else {
                sig.push_str(&type_name(pool, arg));
            }
            sig.push(' ');
            sig.push_str(&name);
        }
        sig.push(')');
    }

    if is_clinit {
        let Some(b) = body else { return Ok(None) };
        let printer = Printer::new(ctx, &b.vt);
        let t_print = std::time::Instant::now();
        let body_text = printer.into_string(&b.body);
        crate::method::phase_hit(3, t_print);
        let mut out = String::new();
        out.push_str(&ind);
        out.push_str("static {\n");
        for line in body_text.lines() {
            if line.is_empty() {
                out.push('\n');
            } else {
                out.push_str(&ind);
                out.push_str("    ");
                out.push_str(line);
                out.push('\n');
            }
        }
        out.push_str(&ind);
        out.push_str("}\n");
        return Ok(Some(out));
    }
    if a & (ACC_ABSTRACT | ACC_NATIVE) != 0 || body.is_none() {
        return Ok(Some(format!("{}{};\n", ind, sig)));
    }
    let Some(b) = body else { return Ok(None) };

    // The printer indents relative to 0; emit_method adds the absolute
    // prefix (ind + one level) per line.
    let mut printer = Printer::new(ctx, &b.vt);
    match &b.desc.ret {
        JavaType::Boolean => {
            printer = printer.with_ret_bool(true);
        }
        JavaType::Char => {
            printer = printer.with_ret_char(true);
        }
        JavaType::Byte => {
            printer = printer.with_ret_narrow(true, false);
        }
        JavaType::Short => {
            printer = printer.with_ret_narrow(false, true);
        }
        _ => {}
    }
    let t_print = std::time::Instant::now();
    let body_text = printer.into_string(&b.body);
    crate::method::phase_hit(3, t_print);

    let mut out = String::new();
    out.push_str(&ind);
    out.push_str(&sig);
    out.push_str(" {\n");
    if !body_text.trim().is_empty() {
        for line in body_text.lines() {
            if line.is_empty() {
                out.push('\n');
            } else {
                out.push_str(&ind);
                out.push_str("    ");
                out.push_str(line);
                out.push('\n');
            }
        }
    }
    out.push_str(&ind);
    out.push_str("}\n");
    Ok(Some(out))
}

// ---------------------------------------------------------------------------
// Naming helpers
// ---------------------------------------------------------------------------

fn indent(depth: usize) -> String {
    "    ".repeat(depth)
}

fn split_name(internal: &str) -> (String, String) {
    match internal.rfind('/') {
        Some(i) => (internal[..i].to_string(), internal[i + 1..].to_string()),
        None => (String::new(), internal.to_string()),
    }
}

/// Dotted source form of an internal name.
pub fn dotted(internal: &str) -> String {
    internal.replace('/', ".").replace('$', ".")
}

fn join_dotted(names: &[String]) -> String {
    names
        .iter()
        .map(|n| dotted(n))
        .collect::<Vec<_>>()
        .join(", ")
}

/// A printable type name (arrays render with `[]` suffixes). Nested class
/// names dot their `$` when the outer chain is known to the pool.
pub fn type_name(pool: &DexPool, t: &JavaType) -> String {
    match t {
        JavaType::Void => "void".into(),
        JavaType::Object(n) => print_class_name(pool, n),
        JavaType::Array(inner) => format!("{}[]", type_name(pool, inner)),
        other => other.to_java(false),
    }
}

/// `com/foo/Outer$Inner` → `com.foo.Outer.Inner` — each `$` dots only when
/// its left side names a known class (literal `$` top-level names survive).
pub fn print_class_name(pool: &DexPool, internal: &str) -> String {
    let mut out = String::new();
    let mut rest: &str = internal;
    loop {
        match rest.find('$') {
            Some(i) => {
                let cand = &rest[..i];
                let known = pool.get(cand).is_some() || cand == internal;
                out.push_str(&cand.replace('/', "."));
                out.push_str(if known { "." } else { "$" });
                rest = &rest[i + 1..];
            }
            None => {
                out.push_str(&rest.replace('/', "."));
                return out;
            }
        }
    }
}

/// Dotted source form of an internal name.
pub fn dotted_pool(pool: &DexPool, internal: &str) -> String {
    print_class_name(pool, internal)
}

/// Unused import silencer.
#[allow(dead_code)]
fn _unused(_: &dyn Fn(&JavaType) -> jdc_core::types::GenericType) {
    let _ = java_type_to_generic;
}
