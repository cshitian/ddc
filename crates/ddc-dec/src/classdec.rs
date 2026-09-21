//! Class-level rendering: header, fields (with static initializers),
//! constructors, methods and nested member classes.

use jdc_core::emit::{escape_string, format_float, Printer};
use jdc_core::types::JavaType;
use jdc_core::Ctx;

use crate::access::*;
use crate::PoolField;
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
/// One registered monitored decompile: the receiver the worker polls at
/// the tail, the class name (for diagnostics), and the deadline counted
/// from the spawn.
pub type PendingMonitor = (
    std::sync::mpsc::Receiver<Result<String, String>>,
    String,
    std::time::Instant,
);

pub fn decompile_class(
    pool: &std::sync::Arc<DexPool>,
    class: &PoolClass,
    opts: &ClassOptions,
    pending: &std::sync::Mutex<Vec<PendingMonitor>>,
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
    // Size the class buffer up front: corpus-average classes render to
    // ~1KB per method — without the reserve the String doubles through
    // 4-6 realloc+copy rounds per class (~2× the final size in memmove).
    // Cap the reserve: weixin's monster classes (hundreds of methods)
    // would reserve megabytes of untouched capacity per class — large
    // blocks take mimalloc's commit/purge path (madvise churn showed up
    // in profiles). 256KB covers the corpus-average class dozens of
    // times over; bigger classes pay a few extra doublings.
    let mut out = String::with_capacity(
        (class.all_methods().count() * 1024).min(256 * 1024) + 512,
    );
    if opts.provenance {
        static BANNER: std::sync::OnceLock<String> = std::sync::OnceLock::new();
        out.push_str(BANNER.get_or_init(|| {
            format!(
                "// Decompiled by https://github.com/ejfkdev/ddc {}\n",
                env!("CARGO_PKG_VERSION")
            )
        }));
        // Provenance: which input image this class was lifted from (jadx's
        // `loaded from: classes.dex` pattern). Byte-stable across runs —
        // deliberately NO timestamp so outputs diff cleanly. Direct
        // push_str: the per-class format! temporaries were 3 allocations
        // × every class in the corpus.
        if let Some(dex) = pool.dex(class.dex_idx) {
            if let Some(label) = pool.dex_labels.get(class.dex_idx) {
                out.push_str("// From: ");
                out.push_str(label);
                out.push_str(" (DEX ");
                out.push_str(&dex.version);
                out.push_str(")\n");
            }
        }
    }
    if let Some(src) = &class.source_file {
        out.push_str("// Source file: ");
        out.push_str(src);
        out.push('\n');
    }
    if class.is_synthetic() {
        out.push_str("// synthetic\n");
    }
    let (pkg, _) = split_name(&class.name);
    if !pkg.is_empty() {
        out.push('\n');
        out.push_str("package ");
        let dotted = pkg.replace('/', ".");
        out.push_str(&sanitize_fq(&dotted));
        out.push_str(";\n");
    }
    out.push('\n');
    // Emit straight into `out`: the intermediate body buffer copied the
    // whole rendered class (corpus-average ~10KB) a second time — pure
    // memmove traffic; the error path discards `out` either way.
    emit_class_body(pool, class, &ctx, opts, &mut out, 0)?;
    Ok(out)
}

/// Render the class header, fields, methods and nested member classes into
/// `out` (used at top level and recursively for nested members).
// `opts` is only consumed by the nested-member recursion below — that
// is its purpose (propagating emission options into inline children).
/// One enum constant: the source identifier plus constructor
/// arguments beyond the compiler-mandated `(String name, int ordinal)`.
use jdc_core::ir::expr::{ConstVal, Expr};
use jdc_core::ir::stmt::Stmt;
struct EnumConst {
    #[allow(dead_code)]
    field: String,
    name: String,
    extra_args: Vec<Expr>,
}

/// Collect enum constants for a true `enum` rendering. Every ACC_ENUM
/// static field must be initialized in `<clinit>` by
/// `Self.field = new Self("NAME", ordinal, ...)` — the shape javac/d8
/// always emit. Returns None (caller falls back to the desugared
/// `/* enum */ class` form) when anything is missing: R8 variance,
/// constant-specific bodies (the field holds an anonymous subclass), or
/// a <clinit> that failed to decompile.
fn collect_enum_constants(
    pool: &DexPool,
    class: &PoolClass,
    ctx: &DexCtx<'_>,
) -> Option<(Vec<EnumConst>, crate::method::MethodBody)> {
    let _ = ctx;
    let const_fields: Vec<&PoolField> = class
        .static_fields
        .iter()
        .filter(|f| f.access & crate::access::ACC_ENUM != 0)
        .collect();
    if const_fields.is_empty() {
        return None;
    }
    let clinit = class.all_methods().find(|m| &*m.name == "<clinit>")?;
    let mut body = decompile_method(pool, class, clinit).ok().flatten()?;

    // R8/d8 split the constant build across an intermediate local:
    //   Self v0 = new Self("NAME", i, ...);
    //   a = v0;                       // sput to the ACC_ENUM field
    //   Self[] v5 = new Self[n]; v5[k] = v0; ...; $VALUES = v5;
    // Pass 1 registers each intermediate (or direct) new; pass 2 binds
    // them to the ACC_ENUM fields; references to the locals are then
    // rewritten into constant identifiers so the $VALUES build keeps
    // compiling once the definitions drop.
    use std::collections::HashMap;
    let mut const_name: Vec<String> = Vec::new();
    let mut const_field: Vec<String> = Vec::new();
    let mut const_extra: Vec<Vec<Expr>> = Vec::new();
    let mut var_of: HashMap<u32, usize> = HashMap::default(); // local id -> const idx
    let mut drop_stmts: Vec<usize> = Vec::new();

    // Collect (immutable borrows) first; the mutable passes come after.
    if !matches!(&body.body, Stmt::Block(_)) {
        return None;
    }

    // Pass 1: definitions. (immutable borrow; rewrite comes later)
    // Rolling reaching-defs of clinit locals for resolving enum-ctor
    // extra args (resolve_enum_arg); `tainted` flips at the first
    // non-straight-line statement — past it, linear-scan defs are no
    // longer provable and Local args reject the enum mode.
    let mut defs: HashMap<u32, &Expr> = HashMap::default();
    let mut tainted = false;
    let self_name: std::sync::Arc<str> = class.name.as_str().into();
    let self_ty =
        jdc_core::ir::expr::TypeRef::J(JavaType::Object(class.name.as_str().into()));
    for (i, st) in match &body.body {
        Stmt::Block(v) => v.iter().enumerate(),
        _ => return None,
    } {
        if let Stmt::LocalDef {
            var,
            init: Some(Expr::New { cls: ncls, args, .. }),
            ..
        } = st
        {
            if ncls.as_ref() == class.name && args.len() >= 2 {
                if let (Expr::Const(ConstVal::Str(n)), Expr::Const(ConstVal::Int(_))) =
                    (&args[0], &args[1])
                {
                    if java_ident(n).as_ref() != &**n || n.is_empty() {
                        return None;
                    }
                    var_of.insert(*var, const_name.len());
                    const_name.push(n.to_string());
                    const_field.push(String::new());
                    const_extra.push(resolve_enum_extras(
                        &args[2..],
                        &defs,
                        tainted,
                        &var_of,
                        &const_name,
                        &self_name,
                        &self_ty,
                    )?);
                    drop_stmts.push(i);
                }
            }
        }
        track_def(st, &mut defs, &mut tainted);
    }

    // Pass 2: sputs to the ACC_ENUM fields (direct new or intermediate).
    let mut defs2: HashMap<u32, &Expr> = HashMap::default();
    let mut tainted2 = false;
    for (i, st) in match &body.body {
        Stmt::Block(v) => v.iter().enumerate(),
        _ => return None,
    } {
        if let Stmt::ExprStmt(Expr::Assign { target, value, .. }) = st {
            if let Expr::Field {
                cls,
                name: fname,
                is_static: true,
                ..
            } = &**target
            {
                if cls.as_ref() != class.name {
                    continue;
                }
                if !const_fields.iter().any(|f| f.name.as_str() == &**fname) {
                    continue;
                }
                if const_field.iter().any(|f| !f.is_empty() && f == &**fname) {
                    return None; // duplicate assignment
                }
                let idx = match &**value {
                    Expr::Local { var, .. } => var_of.get(var).copied()?,
                    Expr::New { cls: ncls, args, .. }
                        if ncls.as_ref() == class.name && args.len() >= 2 =>
                    {
                        if let (Expr::Const(ConstVal::Str(n)), Expr::Const(ConstVal::Int(_))) =
                            (&args[0], &args[1])
                        {
                            if java_ident(n).as_ref() != &**n || n.is_empty() {
                                return None;
                            }
                            let idx = const_name.len();
                            const_name.push(n.to_string());
                            const_field.push(String::new());
                            const_extra.push(resolve_enum_extras(
                                &args[2..],
                                &defs2,
                                tainted2,
                                &var_of,
                                &const_name,
                                &self_name,
                                &self_ty,
                            )?);
                            idx
                        } else {
                            return None;
                        }
                    }
                    _ => return None,
                };
                const_field[idx] = fname.to_string();
                drop_stmts.push(i);
            }
        }
        track_def(st, &mut defs2, &mut tainted2);
    }

    // Every ACC_ENUM field bound, every intermediate matched.
    if const_field.len() != const_fields.len() || const_field.iter().any(|f| f.is_empty()) {
        return None;
    }
    {
        let mut seen: std::collections::HashSet<&str> = std::collections::HashSet::default();
        if !const_name.iter().all(|c| seen.insert(c.as_str())) {
            return None;
        }
    }

    // Pass 3: rewrite references to the intermediate locals into the
    // constant identifiers (static-field reads on Self).
    let var2name: jdc_core::FxHashMap<u32, &str> = var_of
        .iter()
        .map(|(v, &i)| (*v, const_name[i].as_str()))
        .collect();
    crate::passes::rewrite_exprs(&mut body.body, &mut |e| {
        crate::passes::deep_rewrite(e, &mut |x| {
            if let Expr::Local { var, .. } = x {
                if let Some(n) = var2name.get(var) {
                    let name: std::sync::Arc<str> = std::sync::Arc::from(*n);
                    *x = Expr::Field {
                        owner: None,
                        cls: self_name.clone(),
                        name,
                        ty: self_ty.clone(),
                        is_static: true,
                    };
                }
            }
        });
    });

    // Pass 4: drop the definitions and their sputs.
    if let Stmt::Block(vs) = &mut body.body {
        let drop_set: std::collections::HashSet<usize> =
            drop_stmts.iter().copied().collect();
        vs.retain(|_| true);
        let mut idx = 0usize;
        vs.retain(|_| {
            let keep = !drop_set.contains(&idx);
            idx += 1;
            keep
        });
    }
    // The resolved args consumed the clinit locals' readers; prune the
    // now-dead defs from the remnant (impure inits survive as bare
    // expression statements — drop_dead_locals' standard contract).
    crate::passes::drop_dead_locals(&mut body.body);

    let out: Vec<EnumConst> = const_field
        .into_iter()
        .zip(const_name)
        .zip(const_extra)
        .map(|((field, name), extra_args)| EnumConst {
            field,
            name,
            extra_args,
        })
        .collect();
    Some((out, body))
}

/// Update the rolling reaching-def map for enum-arg resolution. Only
/// flat single-target definitions keep the tracking sound; any control
/// flow taints it (a linear scan can no longer prove WHICH definition
/// reaches later capture sites).
fn track_def<'e>(
    st: &'e Stmt,
    defs: &mut std::collections::HashMap<u32, &'e Expr>,
    tainted: &mut bool,
) {
    match st {
        Stmt::LocalDef { var, init, .. } => match init {
            Some(e) => {
                defs.insert(*var, e);
            }
            None => {
                defs.remove(var);
            }
        },
        Stmt::ExprStmt(Expr::Assign { target, value, op, .. }) => {
            if let Expr::Local { var, .. } = &**target {
                if matches!(op, jdc_core::ir::expr::AssignOp::Plain) {
                    defs.insert(*var, value);
                } else {
                    defs.remove(var);
                }
            }
        }
        // Plain expression statements (calls) don't define locals.
        Stmt::ExprStmt(_) => {}
        _ => *tainted = true,
    }
}

/// Resolve every enum-ctor extra arg to a self-contained expression, or
/// reject the enum mode (None). R8 reuses ONE register across all
/// constant constructions — revenuecat's LogIntent builds 11 of 12
/// emoji lists through the same `list` local, reassigned between the
/// `new Self(.., list)` sites — and enum constants render OUTSIDE the
/// clinit where no local is in scope: an unresolved `Local` used to
/// print as the vt-dummy name (`DEBUG(var0)` — per-constant
/// cannot-find). Each Local is replaced by its reaching pure definition
/// (recursively) or, when it names an earlier constant's intermediate,
/// by a static-field reference to that constant. Any expression shape
/// WITHOUT locals passes through untouched (enum args may be arbitrary
/// expressions — BinOp/Cast/Method/New — each renders exactly once per
/// constant, so no duplication concern applies). Only an unresolvable
/// Local (missing/tainted def, depth > 4) rejects the whole enum
/// detection; the class then falls back to plain-field rendering, which
/// always compiles.
fn resolve_enum_extras(
    extras: &[Expr],
    defs: &std::collections::HashMap<u32, &Expr>,
    tainted: bool,
    var_of: &std::collections::HashMap<u32, usize>,
    const_name: &[String],
    self_name: &std::sync::Arc<str>,
    self_ty: &jdc_core::ir::expr::TypeRef,
) -> Option<Vec<Expr>> {
    extras
        .iter()
        .map(|e| {
            let mut out = e.clone();
            let mut fail = false;
            resolve_locals_in(
                &mut out, defs, tainted, var_of, const_name, self_name, self_ty, 0,
                &mut fail,
            );
            if fail {
                None
            } else {
                Some(out)
            }
        })
        .collect()
}

#[allow(clippy::too_many_arguments)]
fn resolve_locals_in(
    e: &mut Expr,
    defs: &std::collections::HashMap<u32, &Expr>,
    tainted: bool,
    var_of: &std::collections::HashMap<u32, usize>,
    const_name: &[String],
    self_name: &std::sync::Arc<str>,
    self_ty: &jdc_core::ir::expr::TypeRef,
    depth: u32,
    fail: &mut bool,
) {
    crate::passes::deep_rewrite(e, &mut |x| {
        if let Expr::Local { var, .. } = x {
            // An earlier constant's intermediate: a static-field read of
            // that constant (declared above — backward reference, legal
            // in enum ctor args).
            if let Some(&ci) = var_of.get(var) {
                if let Some(nm) = const_name.get(ci) {
                    *x = Expr::Field {
                        owner: None,
                        cls: self_name.clone(),
                        name: std::sync::Arc::from(nm.as_str()),
                        ty: self_ty.clone(),
                        is_static: true,
                    };
                    return;
                }
            }
            if tainted || depth > 4 {
                *fail = true;
                return;
            }
            let Some(d) = defs.get(var).copied() else {
                *fail = true;
                return;
            };
            let mut sub = d.clone();
            resolve_locals_in(
                &mut sub, defs, tainted, var_of, const_name, self_name, self_ty,
                depth + 1, fail,
            );
            if *fail {
                return;
            }
            *x = sub;
        }
    });
}

/// Render enum-constant constructor arguments via the shared expression
/// emitter (the VarTable is irrelevant for argument printing — no local
/// names appear — but the API requires one).
fn render_enum_args(ctx: &DexCtx<'_>, pool: &DexPool, args: &[Expr], out: &mut String) {
    let dummy_vt = jdc_core::var::VarTable::default();
    let mut p = Printer::new(ctx, &dummy_vt);
    for (i, a) in args.iter().enumerate() {
        if i > 0 {
            out.push_str(", ");
        }
        p.expr(a, 0, out);
    }
    let _ = pool;
}

#[allow(clippy::only_used_in_recursion)]
fn emit_class_body(
    pool: &DexPool,
    class: &PoolClass,
    ctx: &DexCtx<'_>,
    opts: &ClassOptions,
    out: &mut String,
    depth: usize,
) -> anyhow::Result<()> {
    let ind = indent(depth);
    // The class's own header must use the RENAMED display name — the
    // ctor path (is_init) already renames; a header declaring `class a`
    // while the file/ctor say `a_2` leaves the ctor looking like a
    // method with no return type (MinisApp's Y2.a vs y2.a package
    // case-collision: 2,518 javac parse errors).
    let cname = crate::apply_class_rename(&class.name);
    let (_, simple) = split_name(&cname);
    // A class emitted as its OWN top-level file (depth 0) must declare a
    // flat `$` name — `class Outer.Inner` is not declarable at file
    // scope. An INLINE nested member (depth > 0) declares its own
    // segment inside the parent's body.
    let simple = if depth == 0 {
        simple.to_string()
    } else {
        // R8 names can END in `$`: an empty last `$`-segment would
        // render `class  {` — keep the whole simple name.
        let seg = simple.rsplit('$').next().unwrap_or(&simple);
        if seg.is_empty() {
            simple.to_string()
        } else {
            seg.to_string()
        }
    };
    // A class NAMED `var`-style (taobao ships `tb.var`) cannot be
    // declared — restricted contextual type names escape here and in
    // the ctor, file name, and every type reference.
    let simple = if is_restricted_type_name(&simple) {
        format!("_{simple}")
    } else {
        simple
    };
    let is_iface = class.is_interface();
    let is_enum = class.is_enum();

    let mut head = String::new();
    let a = class.access;
    if a & ACC_PUBLIC != 0 {
        head.push_str("public ");
    }
    // Inline nested members need their `static` (interfaces/annotations
    // are implicitly static; a missing `static` on a member class makes
    // every `new Report(...)` site an "outer instance required" error).
    if depth > 0 && !is_iface && ctx.nested_is_static(&class.name) {
        head.push_str("static ");
    }
    if a & ACC_FINAL != 0 && !is_enum {
        head.push_str("final ");
    }
    if a & ACC_ABSTRACT != 0 && !is_iface {
        head.push_str("abstract ");
    }
    if a & ACC_ANNOTATION != 0 {
        head.push('@');
    }
    let mut enum_consts: Option<(Vec<EnumConst>, crate::method::MethodBody)> = if is_enum {
        collect_enum_constants(pool, class, ctx)
    } else {
        None
    };
    if let Some(ecs) = &enum_consts {
        // True `enum` declaration: constants render in the header, the
        // desugared boilerplate (const fields, their <clinit> inits —
        // stripped by strip_enum_const_inits — and the ACC_ENUM flags)
        // disappears. R8-renamed values()/valueOf() stay (they do not
        // collide with the compiler-generated ones); javac-named ones
        // are skipped at the method loop below.
        head.push_str("enum ");
        head.push_str(&java_ident(&simple));
        let _ = ecs;
    } else if is_enum {
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

    // True-enum constant list: the constants lead the body, ahead of
    // any remaining fields.
    if let Some((ecs, _)) = &enum_consts {
        for (i, ec) in ecs.iter().enumerate() {
            out.push_str(&indent(depth + 1));
            out.push_str(&java_ident(&ec.name));
            if !ec.extra_args.is_empty() {
                let mut line = String::from("(");
                render_enum_args(ctx, pool, &ec.extra_args, &mut line);
                line.push(')');
                out.push_str(&line);
            }
            if i + 1 < ecs.len() {
                out.push_str(",\n");
            } else {
                out.push_str(";\n");
            }
        }
        out.push('\n');
    }

    // Fields.
    let mut field_emitted = false;
    for (i, f) in class.static_fields.iter().enumerate() {
        // Enum constant fields became the header list above.
        if enum_consts.is_some() && f.access & crate::access::ACC_ENUM != 0 {
            continue;
        }
        if field_emitted || !class.instance_fields.is_empty() {
            out.push('\n');
        }
        field_emitted = true;
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
    // Duplicated (name, parameter-types) pairs in one class are javac
    // "method is already defined" errors (weibo: 11.5k hits). Source
    // cannot declare them, so exactly one survives: covariant bridges
    // (`Object get(int)` beside `ByteString get(int)` — the compiler
    // GENERATES bridges), plus R8 output that lost the bridge flag
    // (okio Buffer.clone, interface getView re-declarations). A
    // non-bridge method outranks a bridge for the same signature
    // (bridge bodies are delegation stubs); first occurrence otherwise.
    // Never drop a signature outright — the last method standing for a
    // key is always rendered.
    fn sig_key(m: &PoolMethod) -> (&str, &str) {
        let d: &str = &m.desc;
        let lo = d.find('(').map(|i| i + 1).unwrap_or(0);
        let hi = d.find(')').unwrap_or(d.len());
        (&*m.name, &d[lo..hi])
    }
    let methods: Vec<&PoolMethod> = class.all_methods().collect();
    let mut claim: jdc_core::FxHashMap<(&str, &str), usize> = jdc_core::FxHashMap::default();
    for (i, m) in methods.iter().enumerate() {
        let key = sig_key(m);
        match claim.get(&key) {
            Some(&j)
                if m.access & crate::access::ACC_BRIDGE == 0
                    && methods[j].access & crate::access::ACC_BRIDGE != 0 =>
            {
                claim.insert(key, i);
            }
            None => {
                claim.insert(key, i);
            }
            _ => {}
        }
    }
    let mut emitted_any = !class.static_fields.is_empty() || !class.instance_fields.is_empty();
    for (i, m) in methods.iter().enumerate() {
        if &*m.name == "<clinit>" {
            continue; // rendered after the fields
        }
        if claim.get(&sig_key(m)) != Some(&i) {
            continue;
        }
        // True-enum rendering: javac auto-generates values()/valueOf()
        // — the original-named ones must not re-declare (R8-renamed
        // copies stay, they do not collide).
        if let Some((ecs, _)) = &enum_consts {
            let d = m.parsed_desc();
            let self_arr = d.as_ref().map(|d| d.ret == JavaType::Array(Box::new(JavaType::Object(class.name.as_str().into()))));
            let self_ret = d.as_ref().map(|d| d.ret == JavaType::Object(class.name.as_str().into()));
            let no_args = d.as_ref().map(|d| d.args.is_empty()).unwrap_or(false);
            let one_str = d
                .as_ref()
                .map(|d| d.args.len() == 1 && matches!(d.args[0], JavaType::Object(ref n) if n.as_ref() == "java/lang/String"))
                .unwrap_or(false);
            let static_ = m.is_static();
            if static_ && no_args && self_arr == Some(true) && &*m.name == "values" {
                continue;
            }
            if static_ && one_str && self_ret == Some(true) && &*m.name == "valueOf" {
                continue;
            }
            // Enum constructors must be private in source form.
            let m_owned: Option<PoolMethod> = if &*m.name == "<init>" {
                let mut c = (*m).clone();
                c.access = (c.access & !(crate::access::ACC_PUBLIC | crate::access::ACC_PROTECTED | crate::access::ACC_PRIVATE)) | crate::access::ACC_PRIVATE;
                Some(c)
            } else {
                None
            };
            let m_ref: &PoolMethod = m_owned.as_ref().unwrap_or(m);
            let mark = out.len();
            if emitted_any {
                out.push('\n');
            }
            if emit_method(pool, class, ctx, m_ref, depth + 1, true, out)? {
                emitted_any = true;
            } else {
                out.truncate(mark);
            }
            let _ = ecs;
            continue;
        }
        let mark = out.len();
        if emitted_any {
            out.push('\n');
        }
        if emit_method(pool, class, ctx, m, depth + 1, enum_consts.is_some(), out)? {
            emitted_any = true;
        } else {
            out.truncate(mark);
        }
    }
    // Static initializer. INTERFACES cannot carry a `static { }` block in
    // Java — their clinit only assigns constants, which static_values (or
    // the `= null` default) already render as field initializers; skip
    // the block entirely.
    let skip_clinit = class.is_interface();
    if let Some((_, clinit_body)) = enum_consts.take() {
        // True-enum <clinit>: the constant assignments are already gone;
        // render the remainder (the $VALUES array build) directly.
        // Skip an empty remainder (all statements were constant inits).
        let empty = match &clinit_body.body {
            Stmt::Block(v) => v.iter().all(|s| matches!(s, Stmt::Block(b) if b.is_empty())),
            _ => false,
        };
        if !empty {
            if emitted_any {
                out.push('\n');
            }
            out.push_str(&indent(depth + 1));
            out.push_str("static {\n");
            let p = Printer::new(ctx, &clinit_body.vt);
            let text = p.with_indent(depth + 2).into_string(&clinit_body.body);
            for line in text.lines() {
                if line.trim().is_empty() {
                    continue;
                }
                out.push_str(line);
                out.push('\n');
            }
            out.push_str(&indent(depth + 1));
            out.push_str("}\n");
            emitted_any = true;
        }
    } else if let Some(clinit) = (!skip_clinit)
        .then(|| class.all_methods().find(|m| &*m.name == "<clinit>"))
        .flatten()
    {
        let mark = out.len();
        if emitted_any {
            out.push('\n');
        }
        if emit_method(pool, class, ctx, clinit, depth + 1, false, out)? {
            emitted_any = true;
        } else {
            out.truncate(mark);
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
        let Some(pc) = pool.get(name) else { continue };
        // Only a REAL `outer$tail` name is an inline member: the
        // children index also carries annotation-derived outers
        // (EnclosingClass) with no naming relationship to the child
        // (obfuscated apps pair a 1-char name with a long enclosing
        // descriptor) — the blind slice panicked there (alipay
        // `a.a.a.a.c`, exposed once children_of actually returned data).
        let Some(rest) = name
            .strip_prefix(class.name.as_str())
            .and_then(|t| t.strip_prefix('$'))
        else {
            continue;
        };
        if rest.is_empty() || rest.starts_with('-') {
            continue;
        }
        if ctx.find_outer(name).as_deref() != Some(class.name.as_str()) {
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

// Eight parameters are all load-bearing (pool, field, static value,
// owner class, output, depth, staticness, interface-init requirement);
// bundling them into a struct would obscure each call site.
#[allow(clippy::too_many_arguments)]
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
    let fname = jdc_core::rename::field_display(f_class, &f.name, &f.desc).unwrap_or(&*f.name);
    line.push_str(&java_ident(fname));
    let mut rendered = None;
    if let Some(v) = init {
        rendered = render_static_value(pool, v, f_class);
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
                n.into_owned()
            } else {
                format!("{}.{}", print_class_name(pool, cls), n)
            }
        }
        StaticValue::Other => return None,
    })
}

/// Render one method straight into the class buffer `out`. Returns
/// whether anything was written (skips: no descriptor, deferred to a
/// monitored thread). The old shape returned a per-method String that
/// the caller copied in — one extra full copy of every method body.
/// `enum_promoted`: the class rendered as a true `enum` declaration
/// (constants in the header), which changes what a ctor signature may
/// declare.
fn emit_method(
    pool: &DexPool,
    class: &PoolClass,
    ctx: &DexCtx<'_>,
    m: &PoolMethod,
    depth: usize,
    enum_promoted: bool,
    out: &mut String,
) -> anyhow::Result<bool> {
    let ind = indent(depth);
    let desc = m.parsed_desc();

    // Signature.
    let mut sig = String::with_capacity(192);
    let a = m.access;
    if a & ACC_PUBLIC != 0 {
        sig.push_str("public ");
    } else if a & ACC_PRIVATE != 0 {
        sig.push_str("private ");
    } else if a & ACC_PROTECTED != 0 {
        sig.push_str("protected ");
    }
    let is_clinit = &*m.name == "<clinit>";
    let is_init = &*m.name == "<init>";
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
    let mut body = decompile_method(pool, class, m).ok().flatten();
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

    // Non-static member-inner ctor: the synthetic outer instance rides
    // as args[0] (typed as the direct enclosing class). Every emission
    // site already passes it implicitly — qualified `outer.new Inner(..)`,
    // `this.new Inner(..)` from inside the outer, `super(..)` after
    // skip_outer_arg — so the signature drops the param and the body's
    // references become `Outer.this`. Without this, every construction
    // site fails javac arity ("无法将类…构造器…应用到给定类型" — the
    // guava androidx inner-class families, d8 capture lambdas).
    let mut inner_arg0 = 0usize;
    if is_init {
        let tail = class.name.rsplit('$').next().unwrap_or("");
        let digit_simple = !tail.is_empty() && tail.chars().all(|c| c.is_ascii_digit());
        if let Some(d) = desc.as_ref() {
            if let Some(JavaType::Object(outer)) = d.args.first() {
                // The direct enclosing class: nesting annotation when
                // present, else the `$`-chain parent (find_outer_name —
                // d8 lambdas are `Outer$$ExternalSyntheticLambdaN`, where
                // a plain rsplit leaves a trailing `$`). It must agree
                // with the this$0 type for the rewrite to fire.
                let enclosing: Option<String> = class
                    .nesting
                    .enclosing_class
                    .clone()
                    .or_else(|| crate::find_outer_name(pool, &class.name));
                let direct = enclosing.as_deref() == Some(outer.as_ref());
                if direct && !digit_simple && ctx.class_has_this0(&class.name) {
                    let param0 = body.as_ref().and_then(|b| {
                        b.vt.vars
                            .iter()
                            .find(|v| v.is_param && v.name != "this")
                            .map(|v| v.id)
                    });
                    let written = match (&body, param0) {
                        (Some(b), Some(p0)) => crate::passes::local_is_written(&b.body, p0),
                        _ => false,
                    };
                    if let (Some(p0), false) = (param0, written) {
                        if let Some(b) = body.as_mut() {
                            // this()-delegations to the SAME class drop the
                            // outer arg (all of its ctors share the strip);
                            // a super target joins when it is an inner of
                            // the same enclosing family.
                            let mut eligible: Vec<String> = vec![class.name.clone()];
                            if let Some(sup) = &class.super_name {
                                let sup_enclosing =
                                    crate::find_outer_name(pool, sup);
                                if sup_enclosing.as_deref() == Some(outer.as_ref())
                                    && ctx.class_has_this0(sup)
                                {
                                    eligible.push(sup.clone());
                                }
                            }
                            let renamed = crate::apply_class_rename(outer);
                            let display = dotted(renamed.as_ref());
                            let ty =
                                jdc_core::ir::expr::TypeRef::J(JavaType::Object(outer.clone()));
                            crate::passes::rewrite_inner_ctor_outer_param(
                                &mut b.body,
                                p0,
                                &display,
                                &ty,
                                &eligible,
                            );
                            inner_arg0 = 1;
                        }
                    }
                }
            }
        }
    }

    if is_clinit {
        // `static { ... }` — the caller strips the method name/params.
    } else {
        let Some(d) = &desc else { return Ok(false) };
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
            let base = if depth <= 1 {
                simple.to_string()
            } else {
                // R8 names can END in `$` (`ThreadMsg$$$`): the last
                // `$`-segment is empty — keep the whole simple name.
                let seg = simple.rsplit('$').next().unwrap_or(&simple);
                if seg.is_empty() {
                    simple.to_string()
                } else {
                    seg.to_string()
                }
            };
            let name = if is_restricted_type_name(&base) {
                format!("_{base}")
            } else {
                base
            };
            sig.push_str(&java_ident(&name));
        } else {
            sig.push_str(&type_name(pool, &d.ret));
            sig.push(' ');
            let mname =
                jdc_core::rename::field_display(&class.name, &m.name, &m.desc).unwrap_or(&*m.name);
            sig.push_str(&java_ident(mname));
        }
        sig.push('(');
        // A promoted enum ctor's dex descriptor carries the compiler-
        // synthesized `(String name, int ordinal)` prefix — JLS forbids
        // declaring those (they are implicit in the `A(args)` constant
        // declarations the promotion emits, and strip_enum_ctor_super
        // already removed the `super(name, ordinal, ..)` delegation).
        // Skip the pair in the signature, or every constant declaration
        // fails javac arity ("无法将枚举…构造器…应用到给定类型"). Only
        // when the body never reads the two params — code that genuinely
        // uses them keeps the declared form.
        let mut arg0 = 0;
        if enum_promoted
            && is_init
            && matches!(d.args.first(), Some(JavaType::Object(s)) if s.as_ref() == "java/lang/String")
            && matches!(d.args.get(1), Some(JavaType::Int))
        {
            let refs_ok = body.as_ref().is_some_and(|b| {
                let uses = crate::passes::count_locals_stmts(std::slice::from_ref(&b.body));
                let synthetic: Vec<u32> = b
                    .vt
                    .vars
                    .iter()
                    .filter(|v| v.is_param && v.name != "this")
                    .take(2)
                    .map(|v| v.id)
                    .collect();
                synthetic.iter().all(|id| uses.get(id).copied().unwrap_or(0) == 0)
            });
            if refs_ok {
                arg0 = 2;
            }
        }
        let n = d.args.len();
        let varargs = a & ACC_VARARGS != 0 && n > 0;
        let arg0 = arg0 + inner_arg0;
        for (i, arg) in d.args.iter().enumerate().skip(arg0) {
            if i > arg0 {
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
            // Param names come from dex debug info — obfuscated apps
            // name them `_` (reserved since Java 9) or after keywords.
            sig.push_str(&java_ident(&name));
        }
        sig.push(')');
    }

    if is_clinit {
        let Some(b) = body else { return Ok(false) };
        // Direct render: the printer starts at the method's ABSOLUTE
        // indent and appends into the same buffer that carries the
        // header — no intermediate body string, no per-line re-indent
        // pass (two full copies of every method body saved).
        out.push_str(&ind);
        out.push_str("static {\n");
        let hdr = out.len();
        let printer = Printer::new(ctx, &b.vt)
            .with_indent(depth + 1)
            .with_output(std::mem::take(out));
        let t_print = std::time::Instant::now();
        let mut rendered = printer.into_string(&b.body);
        crate::method::phase_hit(3, t_print);
        if rendered[hdr..].trim().is_empty() {
            rendered.truncate(hdr);
        }
        rendered.push_str(&ind);
        rendered.push_str("}\n");
        *out = rendered;
        return Ok(true);
    }
    if a & (ACC_ABSTRACT | ACC_NATIVE) != 0 || body.is_none() {
        out.push_str(&ind);
        out.push_str(&sig);
        out.push_str(";\n");
        return Ok(true);
    }
    let Some(b) = body else { return Ok(false) };

    // Direct render at the absolute indent level (see the clinit path).
    let mut printer = Printer::new(ctx, &b.vt).with_indent(depth + 1);
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
    out.push_str(&ind);
    out.push_str(&sig);
    out.push_str(" {\n");
    let hdr = out.len();
    let printer = printer.with_output(std::mem::take(out));
    let t_print = std::time::Instant::now();
    let mut rendered = printer.into_string(&b.body);
    crate::method::phase_hit(3, t_print);
    if rendered[hdr..].trim().is_empty() {
        rendered.truncate(hdr);
    }
    rendered.push_str(&ind);
    rendered.push_str("}\n");
    *out = rendered;
    Ok(true)
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
/// Kotlin emits method names like `invokeSuspend$lambda-0` — `-` (and
/// any other non-identifier character) is not legal Java. Deterministic
/// mapping, applied identically at declaration and call sites.
pub(crate) fn java_ident(name: &str) -> std::borrow::Cow<'_, str> {
    // env::var_os is an environ lock+scan — java_ident runs per IDENTIFIER
    // (millions per APK), where it profiled as __NSGetEnviron.
    static DBG_IDENT: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    if *DBG_IDENT.get_or_init(|| std::env::var_os("DDC_DBG_IDENT").is_some()) {
        eprintln!("[ident] {name:?}");
    }
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
            // `_` is a reserved identifier since Java 9 (Alipay's
            // instant-run fields are named `_`) — the `_<name>` mapping
            // turns it into `__`, matching jdc-core's call sites.
            | "_"
    );
    // A simple name may not START with a digit either (WhatsApp nests
    // `X/0Xx`): the declaration site and every reference (jdc-core's
    // sanitize_source_name) prefix the same underscore.
    let digit_start = name.chars().next().is_some_and(|c| c.is_ascii_digit());
    if clean && !keyword && !digit_start {
        std::borrow::Cow::Borrowed(name)
    } else if keyword || digit_start {
        std::borrow::Cow::Owned(format!("_{name}"))
    } else {
        // Non-ASCII single chars (Alipay names a field `支`) map to a
        // lone `_` — itself reserved since Java 9. Escape it.
        let mapped: String = name
            .chars()
            .map(|c| {
                if c.is_ascii_alphanumeric() || c == '_' || c == '$' {
                    c
                } else {
                    '_'
                }
            })
            .collect();
        if mapped == "_" {
            std::borrow::Cow::Owned("__".to_string())
        } else {
            std::borrow::Cow::Owned(mapped)
        }
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
    // `known` must test the ACCUMULATED internal prefix, not the bare
    // inter-`$` segment: the per-segment shape checked `pool.get("a")`
    // for the second level of `s5/o$a$b`, missed, and rendered the
    // undeclarable reference `s5.o.a$b` (找不到符号) for every nested-
    // nested type.
    let mut off = 0usize;
    loop {
        let rest = &internal[off..];
        match rest.find('$') {
            Some(i) => {
                let seg = &rest[..i];
                let prefix = &internal[..off + i];
                let known = pool.get(prefix).is_some()
                    || jdc_core::rename::is_renamed_display(prefix)
                    // The FULL name is not a pool class: this `$` cannot
                    // be a literal name (pool literal classes — an app's
                    // own `View$OnUnhandledKeyEventListener` — keep their
                    // `$` here AND at their declaration), so it can only
                    // be an external framework nesting boundary
                    // (`View$OnClickListener` → `.OnClickListener`).
                    || !pool.get(internal).is_some();
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
                out.push_str(&seg.replace('/', "."));
                out.push_str(if known && tail_ok { "." } else { "$" });
                off += i + 1;
            }
            None => {
                out.push_str(&rest.replace('/', "."));
                return sanitize_ref(&out);
            }
        }
    }
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
            if is_java_keyword_name(seg)
                || is_restricted_type_name(seg)
                || seg.chars().next().is_some_and(|c| c.is_ascii_digit())
            {
                format!("_{seg}")
            } else if seg
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '$')
            {
                seg.to_string()
            } else {
                // Non-ASCII single chars (rimet nests classes named `ˆ`
                // / `ァ`) map to a lone `_` — reserved since Java 9.
                let mapped: String = seg
                    .chars()
                    .map(|c| {
                        if c.is_ascii_alphanumeric() || c == '_' || c == '$' {
                            c
                        } else {
                            '_'
                        }
                    })
                    .collect();
                if mapped == "_" {
                    "__".to_string()
                } else {
                    mapped
                }
            }
        })
        .collect::<Vec<_>>()
        .join(".")
}

/// Restricted contextual TYPE names — legal as member/local names
/// (rt.jar compiles `var` locals), illegal in class declarations and
/// type references. Consulted only on CLASS-name paths.
pub(crate) fn is_restricted_type_name(s: &str) -> bool {
    matches!(s, "var" | "yield" | "record" | "sealed" | "permits")
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
            // `_` is a reserved identifier since Java 9 (Alipay's
            // instant-run fields are named `_`) — the `_<name>` mapping
            // turns it into `__`, matching jdc-core's call sites.
            | "_"
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
