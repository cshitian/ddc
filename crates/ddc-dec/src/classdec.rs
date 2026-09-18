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
        out.push_str(&format!(
            "package {};\n",
            sanitize_fq(&pkg.replace('/', "."))
        ));
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
    // A class emitted as its OWN top-level file (depth 0) must declare a
    // flat `$` name — `class Outer.Inner` is not declarable at file
    // scope. An INLINE nested member (depth > 0) declares its own
    // segment inside the parent's body.
    let simple = if depth == 0 {
        simple.to_string()
    } else {
        simple.rsplit('$').next().unwrap_or(&simple).to_string()
    };
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
        // An enum with constant-specific bodies carries ACC_ABSTRACT —
        // `abstract final` is an illegal modifier combination; abstract
        // (already pushed above) suppresses the hardcoded final.
        let abstract_ = a & ACC_ABSTRACT != 0;
        head.push_str(if abstract_ {
            "/* enum */ class "
        } else {
            "/* enum */ final class "
        });
        head.push_str(&java_ident(&simple));
    } else if is_iface {
        head.push_str("interface ");
        head.push_str(&java_ident(&simple));
    } else {
        head.push_str("class ");
        head.push_str(&java_ident(&simple));
    }
    if is_iface {
        if !class.interfaces.is_empty() {
            head.push_str(" extends ");
            head.push_str(&join_dotted(pool, &class.interfaces));
        }
    } else {
        if let Some(sup) = &class.super_name {
            if sup != "java/lang/Object" && !is_enum {
                head.push_str(" extends ");
                head.push_str(&print_class_name(pool, sup));
            }
        }
        if !class.interfaces.is_empty() {
            head.push_str(if is_iface {
                " extends "
            } else {
                " implements "
            });
            head.push_str(&join_dotted(pool, &class.interfaces));
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
            class.is_interface(),
        );
    }
    if !class.instance_fields.is_empty() && !class.static_fields.is_empty() {
        out.push('\n');
    }
    for (i, f) in class.instance_fields.iter().enumerate() {
        if i > 0 {
            out.push('\n');
        }
        emit_field(pool, f, None, &class.name, out, depth + 1, false, false);
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
    // Static initializer. INTERFACES cannot carry a `static { }` block in
    // Java — their clinit only assigns constants, which static_values (or
    // the `= null` default) already render as field initializers; skip
    // the block entirely.
    let skip_clinit = class.is_interface();
    if let Some(clinit) = (!skip_clinit)
        .then(|| class.all_methods().find(|m| m.name == "<clinit>"))
        .flatten()
    {
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
    require_init: bool,
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
    line.push_str(&java_ident(&f.name));
    let mut rendered = None;
    if let Some(v) = init {
        rendered = render_static_value(pool, v, &f_class);
    }
    if rendered.is_none() && require_init {
        // Interface fields MUST have an initializer in Java; the dex may
        // not carry a static_values entry for a compile-time-constant the
        // compiler folded away. Keep it compilable.
        let default = match desc_type(&f.desc) {
            JavaType::Boolean => "false",
            JavaType::Byte | JavaType::Short | JavaType::Char | JavaType::Int => "0",
            JavaType::Long => "0L",
            JavaType::Float => "0.0F",
            JavaType::Double => "0.0",
            _ => "null",
        };
        rendered = Some(default.to_string());
    }
    if let Some(text) = rendered {
        // A long field holding an `Int(i64)` static value needs the `L`
        // suffix: without it the literal is an int and overflows
        // (`long d = -6343169151696340687` failed javac).
        let text = if matches!(desc_type(&f.desc), JavaType::Long)
            && text.chars().all(|c| c.is_ascii_digit() || c == '-')
        {
            format!("{text}L")
        } else {
            text
        };
        line.push_str(" = ");
        line.push_str(&text);
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

fn render_static_value(pool: &DexPool, v: &StaticValue, owner: &str) -> Option<String> {
    Some(match v {
        StaticValue::Int(i) => i.to_string(),
        StaticValue::Float(f) => format_float(*f as f64, true),
        StaticValue::Double(d) => format_float(*d, false),
        StaticValue::Str(s) => format!("\"{}\"", escape_string(s)),
        StaticValue::Type(t) => format!("{}.class", dotted(t)),
        StaticValue::Boolean(b) => b.to_string(),
        StaticValue::Null => "null".into(),
        StaticValue::Field(cls, name) => {
            let n = java_ident(name);
            if cls == owner {
                n
            } else {
                format!("{}.{}", print_class_name(pool, cls), n)
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
    // `abstract synchronized` is an illegal combination — obfuscated
    // builds mark abstract bridges synchronized (WhatsApp
    // SQLiteOpenHelper).
    if a & (ACC_SYNCHRONIZED | ACC_DECLARED_SYNCHRONIZED) != 0 && a & ACC_ABSTRACT == 0 {
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
            // The ctor name must equal the DECLARED class name of its
            // file: flat `$` at depth 0 (own file), own segment when
            // inlined in the parent at depth > 0. Case-renamed classes
            // use their display name.
            let dname = crate::apply_class_rename(&class.name);
            let (_, simple) = split_name(&dname);
            // emit_method's depth is the METHOD indent = class depth + 1:
            // own-file classes (depth 0 header → method depth 1) need the
            // flat `$` ctor name; inline nested members use their segment.
            let name = if depth <= 1 {
                simple.to_string()
            } else {
                simple.rsplit('$').next().unwrap_or(&simple).to_string()
            };
            sig.push_str(&java_ident(&name));
        } else {
            sig.push_str(&type_name(pool, &d.ret));
            sig.push(' ');
            sig.push_str(&java_ident(&m.name));
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

/// `$`-separated nesting rendered with dots — but ONLY when every
/// segment is a clean Java identifier (a genuine member class chain).
/// Anonymous (`Outer$1`), Kotlin synthetic (`Version$bigInteger$2`,
/// `...$$inlined$collect$1`) and local-class tails are NOT member
/// classes Java can name; the whole name stays flat with `$` (ddc emits
/// them as their own top-level files).
fn java_nested(name: &str) -> String {
    let segs: Vec<&str> = name.split('$').collect();
    let clean = segs.iter().all(|seg| {
        !seg.is_empty()
            && !seg.starts_with(|c: char| c.is_ascii_digit())
            && seg.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
    });
    if clean {
        segs.join(".")
    } else {
        name.replace('$', "$")
    }
}

/// Kotlin emits method names like `invokeSuspend$lambda-0` — `-` (and
/// any other non-identifier character) is not legal Java. Deterministic
/// mapping, applied identically at declaration and call sites.
pub(crate) fn java_ident(name: &str) -> String {
    let clean = name
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '$');
    // Kotlin names fields/methods `default` (Companion.default) — no Java
    // program can declare or reference a keyword; the identical mapping
    // lives in jdc-core's call-site sanitizer.
    let keyword = matches!(
        name,
        "abstract"
            | "assert"
            | "boolean"
            | "break"
            | "byte"
            | "case"
            | "catch"
            | "char"
            | "class"
            | "const"
            | "continue"
            | "default"
            | "do"
            | "double"
            | "else"
            | "enum"
            | "extends"
            | "final"
            | "finally"
            | "float"
            | "for"
            | "goto"
            | "if"
            | "implements"
            | "import"
            | "instanceof"
            | "int"
            | "interface"
            | "long"
            | "native"
            | "new"
            | "package"
            | "private"
            | "protected"
            | "public"
            | "return"
            | "short"
            | "static"
            | "strictfp"
            | "super"
            | "switch"
            | "synchronized"
            | "this"
            | "throw"
            | "throws"
            | "transient"
            | "try"
            | "void"
            | "volatile"
            | "while"
            | "true"
            | "false"
            | "null"
    );
    // A simple name may not START with a digit either (WhatsApp nests
    // `X/0Xx`): the declaration site and every reference (jdc-core's
    // sanitize_source_name) prefix the same underscore.
    let digit_start = name.chars().next().is_some_and(|c| c.is_ascii_digit());
    if clean && !keyword && !digit_start {
        name.to_string()
    } else if keyword || digit_start {
        format!("_{name}")
    } else {
        name.chars()
            .map(|c| {
                if c.is_ascii_alphanumeric() || c == '_' || c == '$' {
                    c
                } else {
                    '_'
                }
            })
            .collect()
    }
}

fn split_name(internal: &str) -> (String, String) {
    match internal.rfind('/') {
        Some(i) => (internal[..i].to_string(), internal[i + 1..].to_string()),
        None => (String::new(), internal.to_string()),
    }
}

/// Dotted source form of an internal name.
pub fn dotted(internal: &str) -> String {
    let mut out = internal.replace('/', ".");
    // `$` → `.` only when the following segment can start a Java
    // identifier (anonymous/synthetic tails stay `$`).
    let mut i = 0;
    while let Some(p) = out[i..].find('$') {
        let at = i + p;
        // A LEADING `$` (ProGuard keeps `$Gson$Types`) is part of the
        // source name — dotting it produced a leading `.Gson.Types`.
        let head_ok = at > 0
            && out[..at]
                .chars()
                .next_back()
                .is_some_and(|c| c.is_ascii_alphanumeric() || c == '_');
        let tail_ok = out[at + 1..]
            .chars()
            .next()
            .is_some_and(|c| c.is_ascii_alphabetic() || c == '_');
        if tail_ok && head_ok {
            out.replace_range(at..at + 1, ".");
            i = at + 1;
        } else {
            i = at + 1;
        }
    }
    // Every `.`-segment must start an identifier: WhatsApp's `X/0Hl`
    // reached `extends` with the digit start unmapped.
    sanitize_fq(&out)
}

fn join_dotted(pool: &DexPool, names: &[String]) -> String {
    names
        .iter()
        .map(|n| print_class_name(pool, n))
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
    let cow = crate::apply_class_rename(internal);
    let internal: &str = &cow;
    let mut out = String::new();
    let mut rest: &str = internal;
    loop {
        match rest.find('$') {
            Some(i) => {
                let cand = &rest[..i];
                let known = pool.get(cand).is_some() || cand == internal;
                // The `$` may only become a nesting dot when the tail
                // segment STARTS a Java identifier: R8's desugared-
                // library names carry `$` inside PACKAGE paths
                // (`j$/util/...` dotted into `j..util`) and suffixes
                // like `Collection$-EL` or anonymous `RequestId$1`
                // cannot be dotted under any reading.
                let tail_ok = rest[i + 1..]
                    .chars()
                    .next()
                    .is_some_and(|c| c.is_ascii_alphabetic() || c == '_');
                out.push_str(&cand.replace('/', "."));
                out.push_str(if known && tail_ok { "." } else { "$" });
                rest = &rest[i + 1..];
            }
            None => {
                let seg = rest.replace('/', ".");
                out.push_str(&seg);
                return sanitize_ref(&out);
            }
        }
    }
    sanitize_ref(&out)
}

/// Class-file names may contain characters Java source identifiers
/// cannot (`Collection$-EL`); the deterministic mapping matches the
/// declaration sites (java_ident).
/// Every `.`-segment of a fully-qualified name must start a Java
/// identifier: obfuscators emit `package do;` and `..badge.new..` paths.
pub(crate) fn sanitize_fq(dotted: &str) -> String {
    dotted
        .split('.')
        .map(|seg| {
            if is_java_keyword_name(seg) || seg.chars().next().is_some_and(|c| c.is_ascii_digit()) {
                format!("_{seg}")
            } else if seg
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '$')
            {
                seg.to_string()
            } else {
                seg.chars()
                    .map(|c| {
                        if c.is_ascii_alphanumeric() || c == '_' || c == '$' {
                            c
                        } else {
                            '_'
                        }
                    })
                    .collect()
            }
        })
        .collect::<Vec<_>>()
        .join(".")
}

fn is_java_keyword_name(s: &str) -> bool {
    matches!(
        s,
        "abstract"
            | "assert"
            | "boolean"
            | "break"
            | "byte"
            | "case"
            | "catch"
            | "char"
            | "class"
            | "const"
            | "continue"
            | "default"
            | "do"
            | "double"
            | "else"
            | "enum"
            | "extends"
            | "final"
            | "finally"
            | "float"
            | "for"
            | "goto"
            | "if"
            | "implements"
            | "import"
            | "instanceof"
            | "int"
            | "interface"
            | "long"
            | "native"
            | "new"
            | "package"
            | "private"
            | "protected"
            | "public"
            | "return"
            | "short"
            | "static"
            | "strictfp"
            | "super"
            | "switch"
            | "synchronized"
            | "this"
            | "throw"
            | "throws"
            | "transient"
            | "try"
            | "void"
            | "volatile"
            | "while"
            | "true"
            | "false"
            | "null"
    )
}

fn sanitize_ref(name: &str) -> String {
    sanitize_fq(name)
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
