//! Post-convert refinement passes for DEX-lifted statement trees.
//!
//! The converter hands back a correct-but-raw tree; these passes restore the
//! source shapes a register machine loses: catch parameter binding,
//! copy-forwarding (single-use temporaries), if/else→ternary folding,
//! `StringBuilder` chain → `+` concatenation, `synchronized` recovery from
//! the d8 monitor pattern, erased-type inference, boolean and null
//! comparisons, and declaration hygiene.

// The tree-walker match arms intentionally mirror the statement grammar
// one level at a time; collapsing the nested `if let`s into outer match
// arms would trade per-arm clarity for lint silence.
#![allow(clippy::collapsible_match)]

use std::collections::HashSet;

// The tree-walker match arms intentionally mirror the statement grammar
// one level at a time; collapsing the nested `if let`s into outer match
// arms would trade per-arm clarity for lint silence.
use jdc_core::ir::build::has_side_effects;
use jdc_core::ir::expr::{AssignOp, BinOp, ConcatPart, ConstVal, Expr, TypeRef, UnOp};
use jdc_core::ir::stmt::{CaseGroup, Catch, Stmt};
use jdc_core::types::{JavaType, MethodDescriptor};
use jdc_core::var::VarTable;

use crate::lift::MethodEnv;

// ---------------------------------------------------------------------------
// Generic tree walking
// ---------------------------------------------------------------------------

/// Deep expression rewrite over a statement tree.
pub fn rewrite_exprs<F: FnMut(&mut Expr)>(s: &mut Stmt, f: &mut F) {
    walk_stmt_exprs(s, f);
}

fn walk_stmt_exprs<F: FnMut(&mut Expr)>(s: &mut Stmt, f: &mut F) {
    match s {
        Stmt::Block(v) => {
            for x in v.iter_mut() {
                walk_stmt_exprs(x, f);
            }
        }
        Stmt::ExprStmt(e) | Stmt::Throw(e) | Stmt::MonitorEnter(e) | Stmt::MonitorExit(e) => {
            f(e);
        }
        Stmt::Return(Some(e)) => f(e),
        Stmt::LocalDef { init, .. } => {
            if let Some(e) = init {
                f(e);
            }
        }
        Stmt::If {
            cond,
            then_stmt,
            else_stmt,
        } => {
            f(cond);
            walk_stmt_exprs(then_stmt, f);
            if let Some(e) = else_stmt {
                walk_stmt_exprs(e, f);
            }
        }
        Stmt::While { cond, body } => {
            f(cond);
            walk_stmt_exprs(body, f);
        }
        Stmt::DoWhile { body, cond } => {
            walk_stmt_exprs(body, f);
            f(cond);
        }
        Stmt::For {
            init,
            cond,
            update,
            body,
        } => {
            for x in init.iter_mut() {
                walk_stmt_exprs(x, f);
            }
            if let Some(c) = cond {
                f(c);
            }
            for u in update.iter_mut() {
                f(u);
            }
            walk_stmt_exprs(body, f);
        }
        Stmt::ForEach { iterable, body, .. } => {
            f(iterable);
            walk_stmt_exprs(body, f);
        }
        Stmt::Switch {
            selector,
            cases,
            default,
            ..
        } => {
            f(selector);
            for c in cases {
                for x in c.body.iter_mut() {
                    walk_stmt_exprs(x, f);
                }
                if let Some(g) = &mut c.guard {
                    f(g);
                }
            }
            if let Some(d) = default {
                walk_stmt_exprs(d, f);
            }
        }
        Stmt::Try {
            body,
            catches,
            finally,
        } => {
            walk_stmt_exprs(body, f);
            for c in catches {
                walk_stmt_exprs(&mut c.body, f);
            }
            if let Some(fl) = finally {
                walk_stmt_exprs(fl, f);
            }
        }
        Stmt::TryWithResources {
            resources,
            body,
            catches,
            finally,
        } => {
            for x in resources.iter_mut() {
                walk_stmt_exprs(x, f);
            }
            walk_stmt_exprs(body, f);
            for c in catches {
                walk_stmt_exprs(&mut c.body, f);
            }
            if let Some(fl) = finally {
                walk_stmt_exprs(fl, f);
            }
        }
        Stmt::Assert { cond, msg } => {
            f(cond);
            if let Some(m) = msg {
                f(m);
            }
        }
        Stmt::Synchronized { lock, body } => {
            f(lock);
            walk_stmt_exprs(body, f);
        }
        Stmt::TernaryValue { e } => f(e),
        Stmt::Labeled { body, .. } => walk_stmt_exprs(body, f),
        Stmt::Goto(_) | Stmt::Label(_) | Stmt::Break(_) | Stmt::Continue(_) => {}
        _ => {}
    }
}

/// Visit every expression (immutable).
fn visit_exprs<F: FnMut(&Expr)>(e: &Expr, f: &mut F) {
    f(e);
    for_each_child(e, &mut |c| visit_exprs(c, f));
}

fn for_each_child<F: FnMut(&Expr)>(e: &Expr, f: &mut F) {
    match e {
        Expr::Un { e, .. } | Expr::Cast { e, .. } | Expr::InstanceOf { e, .. } => f(e),
        Expr::Bin { l, r, .. } => {
            f(l);
            f(r);
        }
        Expr::Cond { c, t, f: fe } => {
            f(c);
            f(t);
            f(fe);
        }
        Expr::Assign { target, value, .. } => {
            f(target);
            f(value);
        }
        Expr::PreIncDec { e, .. } | Expr::PostIncDec { e, .. } => f(e),
        Expr::Field { owner, .. } => {
            if let Some(o) = owner {
                f(o);
            }
        }
        Expr::Method { owner, args, .. } => {
            if let Some(o) = owner {
                f(o);
            }
            for a in args {
                f(a);
            }
        }
        Expr::ArrayIndex { array, index } => {
            f(array);
            f(index);
        }
        Expr::New { args, .. } => {
            for a in args {
                f(a);
            }
        }
        Expr::NewArray { dims, init, .. } => {
            for d in dims {
                f(d);
            }
            if let Some(v) = init {
                for x in v {
                    f(x);
                }
            }
        }
        Expr::NewMultiArray { dims, .. } => {
            for d in dims {
                f(d);
            }
        }
        Expr::StringConcat(parts) => {
            for p in parts {
                if let ConcatPart::Str(x) = p {
                    f(x);
                }
            }
        }
        Expr::Invokedynamic { args, .. } => {
            for a in args {
                f(a);
            }
        }
        Expr::AnonNew { args, .. } => {
            for a in args {
                f(a);
            }
        }
        _ => {}
    }
}

/// Mutable child walk (one level).
fn for_each_child_mut<F: FnMut(&mut Expr)>(e: &mut Expr, f: &mut F) {
    match e {
        Expr::Un { e, .. } | Expr::Cast { e, .. } | Expr::InstanceOf { e, .. } => f(e),
        Expr::Bin { l, r, .. } => {
            f(l);
            f(r);
        }
        Expr::Cond { c, t, f: fe } => {
            f(c);
            f(t);
            f(fe);
        }
        Expr::Assign { target, value, .. } => {
            f(target);
            f(value);
        }
        Expr::PreIncDec { e, .. } | Expr::PostIncDec { e, .. } => f(e),
        Expr::Field { owner, .. } => {
            if let Some(o) = owner {
                f(o);
            }
        }
        Expr::Method { owner, args, .. } => {
            if let Some(o) = owner {
                f(o);
            }
            for a in args.iter_mut() {
                f(a);
            }
        }
        Expr::ArrayIndex { array, index } => {
            f(array);
            f(index);
        }
        Expr::New { args, .. } => {
            for a in args.iter_mut() {
                f(a);
            }
        }
        Expr::NewArray { dims, init, .. } => {
            for d in dims.iter_mut() {
                f(d);
            }
            if let Some(v) = init {
                for x in v.iter_mut() {
                    f(x);
                }
            }
        }
        Expr::NewMultiArray { dims, .. } => {
            for d in dims.iter_mut() {
                f(d);
            }
        }
        Expr::StringConcat(parts) => {
            for p in parts {
                if let ConcatPart::Str(x) = p {
                    f(x);
                }
            }
        }
        Expr::Invokedynamic { args, .. } => {
            for a in args.iter_mut() {
                f(a);
            }
        }
        Expr::AnonNew { args, .. } => {
            for a in args.iter_mut() {
                f(a);
            }
        }
        _ => {}
    }
}

/// Deep mutable expression rewrite.
fn deep_rewrite<F: FnMut(&mut Expr)>(e: &mut Expr, f: &mut F) {
    f(e);
    for_each_child_mut(e, &mut |c| deep_rewrite(c, f));
}

fn collect_vars(e: &Expr, out: &mut HashSet<u32>) {
    visit_exprs(e, &mut |x| {
        if let Expr::Local { var, .. } = x {
            out.insert(*var);
        }
    });
}

/// Collect variable references (reads; `assignments` adds assignment
/// targets). Single-pass recursion — the previous shape wrapped a
/// self-recursive closure in `walk_all`, visiting every subtree twice over
/// (exponential in nesting depth).
fn stmt_collect_vars(s: &Stmt, out: &mut HashSet<u32>, assignments: bool) {
    match s {
        Stmt::Block(v) => {
            for x in v {
                stmt_collect_vars(x, out, assignments);
            }
        }
        Stmt::ExprStmt(Expr::Assign { target, value, .. }) => {
            if let Expr::Local { var, .. } = &**target {
                if assignments {
                    out.insert(*var);
                }
            } else {
                collect_vars(target, out);
            }
            collect_vars(value, out);
        }
        Stmt::ExprStmt(e) | Stmt::Throw(e) | Stmt::MonitorEnter(e) | Stmt::MonitorExit(e) => {
            collect_vars(e, out)
        }
        Stmt::Return(Some(e)) => collect_vars(e, out),
        Stmt::LocalDef { var, init, .. } => {
            if assignments {
                out.insert(*var);
            }
            if let Some(e) = init {
                collect_vars(e, out);
            }
        }
        Stmt::If {
            cond,
            then_stmt,
            else_stmt,
        } => {
            collect_vars(cond, out);
            stmt_collect_vars(then_stmt, out, assignments);
            if let Some(e) = else_stmt {
                stmt_collect_vars(e, out, assignments);
            }
        }
        Stmt::While { cond, body } => {
            collect_vars(cond, out);
            stmt_collect_vars(body, out, assignments);
        }
        Stmt::DoWhile { body, cond } => {
            stmt_collect_vars(body, out, assignments);
            collect_vars(cond, out);
        }
        Stmt::For {
            init,
            cond,
            update,
            body,
        } => {
            for x in init {
                stmt_collect_vars(x, out, assignments);
            }
            if let Some(c) = cond {
                collect_vars(c, out);
            }
            for u in update {
                collect_vars(u, out);
            }
            stmt_collect_vars(body, out, assignments);
        }
        Stmt::ForEach {
            var,
            iterable,
            body,
            ..
        } => {
            if assignments {
                out.insert(*var);
            }
            collect_vars(iterable, out);
            stmt_collect_vars(body, out, assignments);
        }
        Stmt::Switch {
            selector,
            cases,
            default,
            ..
        } => {
            collect_vars(selector, out);
            for c in cases {
                for x in &c.body {
                    stmt_collect_vars(x, out, assignments);
                }
            }
            if let Some(d) = default {
                stmt_collect_vars(d, out, assignments);
            }
        }
        Stmt::Try {
            body,
            catches,
            finally,
        } => {
            stmt_collect_vars(body, out, assignments);
            for c in catches {
                stmt_collect_vars(&c.body, out, assignments);
            }
            if let Some(f) = finally {
                stmt_collect_vars(f, out, assignments);
            }
        }
        Stmt::TryWithResources {
            resources,
            body,
            catches,
            finally,
        } => {
            for x in resources {
                stmt_collect_vars(x, out, assignments);
            }
            stmt_collect_vars(body, out, assignments);
            for c in catches {
                stmt_collect_vars(&c.body, out, assignments);
            }
            if let Some(f) = finally {
                stmt_collect_vars(f, out, assignments);
            }
        }
        Stmt::Synchronized { lock, body } => {
            collect_vars(lock, out);
            stmt_collect_vars(body, out, assignments);
        }
        Stmt::Assert { cond, msg } => {
            collect_vars(cond, out);
            if let Some(m) = msg {
                collect_vars(m, out);
            }
        }
        Stmt::Labeled { body, .. } => stmt_collect_vars(body, out, assignments),
        _ => {}
    }
}

fn walk_all<F: FnMut(&Stmt)>(s: &Stmt, f: &mut F) {
    f(s);
    match s {
        Stmt::Block(v) => {
            for x in v {
                walk_all(x, f);
            }
        }
        Stmt::If {
            then_stmt,
            else_stmt,
            ..
        } => {
            walk_all(then_stmt, f);
            if let Some(e) = else_stmt {
                walk_all(e, f);
            }
        }
        Stmt::While { body, .. } | Stmt::DoWhile { body, .. } => walk_all(body, f),
        Stmt::For { init, body, .. } => {
            for x in init {
                walk_all(x, f);
            }
            walk_all(body, f);
        }
        Stmt::ForEach { body, .. } => walk_all(body, f),
        Stmt::Switch { cases, default, .. } => {
            for c in cases {
                for x in &c.body {
                    walk_all(x, f);
                }
            }
            if let Some(d) = default {
                walk_all(d, f);
            }
        }
        Stmt::Try {
            body,
            catches,
            finally,
        } => {
            walk_all(body, f);
            for c in catches {
                walk_all(&c.body, f);
            }
            if let Some(fl) = finally {
                walk_all(fl, f);
            }
        }
        Stmt::TryWithResources {
            resources,
            body,
            catches,
            finally,
        } => {
            for x in resources {
                walk_all(x, f);
            }
            walk_all(body, f);
            for c in catches {
                walk_all(&c.body, f);
            }
            if let Some(fl) = finally {
                walk_all(fl, f);
            }
        }
        Stmt::Synchronized { body, .. } | Stmt::Labeled { body, .. } => walk_all(body, f),
        _ => {}
    }
}

// ---------------------------------------------------------------------------
// Passes
// ---------------------------------------------------------------------------

/// Bind catch parameters: the handler's first statement (a bare LocalDef
/// from move-exception) becomes the catch variable.
pub fn bind_catches(s: &mut Stmt, vt: &mut VarTable) {
    match s {
        Stmt::Try {
            body,
            catches,
            finally,
        } => {
            bind_catches(body, vt);
            for c in catches.iter_mut() {
                if c.var == u32::MAX {
                    let stored = match c.body.as_ref() {
                        Stmt::Block(v) => match v.first() {
                            Some(Stmt::LocalDef { var, .. }) => Some(*var),
                            Some(Stmt::ExprStmt(Expr::Assign { target, .. })) => match &**target {
                                Expr::Local { var, .. } => Some(*var),
                                _ => None,
                            },
                            _ => None,
                        },
                        _ => None,
                    };
                    if let Some(v) = stored {
                        let exc = c
                            .exc
                            .first()
                            .cloned()
                            .unwrap_or_else(|| "java/lang/Throwable".into());
                        let slot = vt.var(v).slot;
                        let name = "e".to_string();
                        let new_var =
                            vt.add_catch_var(slot, name, TypeRef::J(JavaType::Object(exc)));
                        if let Stmt::Block(vs) = c.body.as_mut() {
                            vs.remove(0);
                        }
                        rewrite_local_refs(c.body.as_mut(), v, new_var);
                        c.var = new_var;
                    }
                }
                bind_catches(&mut c.body, vt);
            }
            if let Some(f) = finally {
                bind_catches(f.as_mut(), vt);
            }
        }
        Stmt::Block(v) => {
            for x in v.iter_mut() {
                bind_catches(x, vt);
            }
        }
        Stmt::If {
            then_stmt,
            else_stmt,
            ..
        } => {
            bind_catches(then_stmt, vt);
            if let Some(e) = else_stmt {
                bind_catches(e, vt);
            }
        }
        Stmt::While { body, .. } | Stmt::DoWhile { body, .. } => bind_catches(body, vt),
        Stmt::For { init, body, .. } => {
            for x in init.iter_mut() {
                bind_catches(x, vt);
            }
            bind_catches(body, vt);
        }
        Stmt::ForEach { body, .. }
        | Stmt::Labeled { body, .. }
        | Stmt::Synchronized { body, .. } => bind_catches(body, vt),
        Stmt::Switch { cases, default, .. } => {
            for c in cases.iter_mut() {
                for x in c.body.iter_mut() {
                    bind_catches(x, vt);
                }
            }
            if let Some(d) = default {
                bind_catches(d, vt);
            }
        }
        _ => {}
    }
}

fn rewrite_local_refs(s: &mut Stmt, from: u32, to: u32) {
    rewrite_exprs(s, &mut |e| {
        deep_rewrite(e, &mut |x| {
            if let Expr::Local { var, .. } = x {
                if *var == from {
                    *var = to;
                }
            }
        });
    });
}

/// Flatten blocks, drop empty ones and trailing no-op statements.
pub fn cleanup(s: &mut Stmt) {
    jdc_core::ir::stmt::flatten(s);
    strip_empty(s);
    merge_singleton_stmts(s);
}

fn strip_empty(s: &mut Stmt) {
    match s {
        Stmt::Block(v) => {
            v.retain(|x| !x.is_empty_block());
            for x in v.iter_mut() {
                strip_empty(x);
            }
        }
        Stmt::If {
            then_stmt,
            else_stmt,
            ..
        } => {
            strip_empty(then_stmt);
            if let Some(e) = else_stmt {
                strip_empty(e);
                if e.is_empty_block() {
                    *else_stmt = None;
                }
            }
        }
        Stmt::While { body, .. } | Stmt::DoWhile { body, .. } => strip_empty(body),
        Stmt::For { init, body, .. } => {
            init.retain(|x| !x.is_empty_block());
            strip_empty(body);
        }
        Stmt::ForEach { body, .. } => strip_empty(body),
        Stmt::Switch { cases, default, .. } => {
            for c in cases {
                c.body.retain(|x| !x.is_empty_block());
            }
            if let Some(d) = default {
                strip_empty(d);
            }
        }
        Stmt::Try {
            body,
            catches,
            finally,
        } => {
            strip_empty(body);
            for c in catches {
                strip_empty(&mut c.body);
            }
            if let Some(f) = finally {
                strip_empty(f);
            }
        }
        Stmt::Synchronized { body, .. } | Stmt::Labeled { body, .. } => strip_empty(body),
        _ => {}
    }
}

fn merge_singleton_stmts(s: &mut Stmt) {
    if let Stmt::Block(v) = s {
        for x in v.iter_mut() {
            merge_singleton_stmts(x);
        }
    }
}

/// Drop statements after a definite terminator within a block.
pub fn prune_unreachable(s: &mut Stmt) {
    if let Stmt::Block(v) = s {
        let mut cut: Option<usize> = None;
        for (i, x) in v.iter().enumerate() {
            if matches!(x, Stmt::Return(_) | Stmt::Throw(_)) {
                cut = Some(i + 1);
                break;
            }
        }
        if let Some(c) = cut {
            if c < v.len() {
                v.truncate(c);
            }
        }
        for x in v.iter_mut() {
            prune_unreachable(x);
        }
    } else {
        walk_mut(s, &mut prune_unreachable);
    }
}

fn walk_mut<F: FnMut(&mut Stmt)>(s: &mut Stmt, f: &mut F) {
    match s {
        Stmt::Block(v) => {
            for x in v.iter_mut() {
                f(x);
            }
        }
        Stmt::If {
            then_stmt,
            else_stmt,
            ..
        } => {
            f(then_stmt);
            if let Some(e) = else_stmt {
                f(e);
            }
        }
        Stmt::While { body, .. } | Stmt::DoWhile { body, .. } => f(body),
        Stmt::For { init, body, .. } => {
            for x in init.iter_mut() {
                f(x);
            }
            f(body);
        }
        Stmt::ForEach { body, .. } => f(body),
        Stmt::Switch { cases, default, .. } => {
            for c in cases {
                for x in c.body.iter_mut() {
                    f(x);
                }
            }
            if let Some(d) = default {
                f(d);
            }
        }
        Stmt::Try {
            body,
            catches,
            finally,
        } => {
            f(body);
            for c in catches {
                f(&mut c.body);
            }
            if let Some(fl) = finally {
                f(fl);
            }
        }
        Stmt::Synchronized { body, .. } | Stmt::Labeled { body, .. } => f(body),
        _ => {}
    }
}

/// Count LocalDef statements (pipeline diagnostics).
pub fn count_localdefs(s: &Stmt, out: &mut usize) {
    if matches!(s, Stmt::LocalDef { .. }) {
        *out += 1;
    }
    walk_all(s, &mut |x| {
        if matches!(x, Stmt::LocalDef { .. }) {
            *out += 1;
        }
    });
}

/// Drop a trailing `return;` (d8's explicit return-void at method end).
pub fn strip_trailing_void_return(s: &mut Stmt) {
    if let Stmt::Block(v) = s {
        while let Some(Stmt::Return(None)) = v.last() {
            v.pop();
        }
    }
}

pub fn prepend_comment(s: &mut Stmt, text: String) {
    let stmt = Stmt::Comment(text);
    match s {
        Stmt::Block(v) => v.insert(0, stmt),
        other => {
            let inner = std::mem::replace(other, Stmt::Block(vec![]));
            *other = Stmt::Block(vec![stmt, inner]);
        }
    }
}

/// Fused expression rewrites that each used to walk the whole tree:
/// residual cmp sentinels, object-null comparisons, const-first compares.
/// One traversal, three rules — the separate walks were a top profile cost.
pub fn fused_expr_rewrites(s: &mut Stmt, vt: &VarTable) {
    // var ids are dense: a byte table beats a HashSet lookup.
    let mut obj_vars: Vec<bool> = Vec::with_capacity(vt.vars.len());
    let mut any_obj = false;
    for v in &vt.vars {
        let is_obj = v.ty.erased().is_reference();
        if is_obj {
            any_obj = true;
        }
        obj_vars.push(is_obj);
    }
    rewrite_exprs(s, &mut |e| {
        deep_rewrite(e, &mut |x| {
            // 1. cmp sentinels.
            if let Expr::Invokedynamic { name, args, .. } = x {
                if name.starts_with('\0') && args.len() == 2 {
                    let (cls, ty) = match name.as_str() {
                        "\0cmp-long" => ("java/lang/Long", JavaType::Long),
                        "\0cmpl-float" | "\0cmpg-float" => ("java/lang/Float", JavaType::Float),
                        _ => ("java/lang/Double", JavaType::Double),
                    };
                    let desc = MethodDescriptor {
                        args: vec![ty.clone(), ty],
                        ret: JavaType::Int,
                    };
                    *x = Expr::Method {
                        owner: None,
                        cls: cls.into(),
                        name: "compare".into(),
                        desc,
                        args: args.clone(),
                        is_static: true,
                        is_interface: false,
                        is_special: false,
                        is_super: false,
                        is_dynamic: false,
                        type_args: vec![],
                    };
                    return;
                }
            }
            // 2. null compares.
            if any_obj {
                if let Expr::Bin { op, l, r, .. } = x {
                    if matches!(op, BinOp::Eq | BinOp::Ne) {
                        let rewrite = |side: &mut Expr, other: &Expr| {
                            if let Expr::Const(ConstVal::Int(0)) = other {
                                if let Expr::Local { var, .. } = &*side {
                                    if obj_vars.get(*var as usize).copied().unwrap_or(false) {
                                        *side = Expr::Const(ConstVal::Null);
                                    }
                                }
                            }
                        };
                        let lo = l.clone();
                        let ro = r.clone();
                        rewrite(l, &ro);
                        rewrite(r, &lo);
                    }
                }
            }
            // 3. const-first compares.
            if let Expr::Bin { op, l, r, .. } = x {
                if matches!(
                    op,
                    BinOp::Eq | BinOp::Ne | BinOp::Lt | BinOp::Ge | BinOp::Gt | BinOp::Le
                ) {
                    let l_const = matches!(&**l, Expr::Const(_));
                    let r_var = matches!(&**r, Expr::Local { .. });
                    if l_const && r_var {
                        std::mem::swap(l, r);
                    }
                }
            }
        });
    });
}

/// Replace residual cmp sentinels (`\0cmp*` Invokedynamic markers that never
/// reached a condition) with library compare calls.
#[allow(dead_code)]
pub fn desugar_cmp_residuals(s: &mut Stmt) {
    rewrite_exprs(s, &mut |e| {
        deep_rewrite(e, &mut |x| {
            if let Expr::Invokedynamic { name, args, .. } = x {
                if name.starts_with('\0') && args.len() == 2 {
                    let (cls, ty) = match name.as_str() {
                        "\0cmp-long" => ("java/lang/Long", JavaType::Long),
                        "\0cmpl-float" | "\0cmpg-float" => ("java/lang/Float", JavaType::Float),
                        _ => ("java/lang/Double", JavaType::Double),
                    };
                    let desc = jdc_core::types::MethodDescriptor {
                        args: vec![ty.clone(), ty],
                        ret: JavaType::Int,
                    };
                    *x = Expr::Method {
                        owner: None,
                        cls: cls.into(),
                        name: "compare".into(),
                        desc,
                        args: args.clone(),
                        is_static: true,
                        is_interface: false,
                        is_special: false,
                        is_super: false,
                        is_dynamic: false,
                        type_args: vec![],
                    };
                }
            }
        });
    });
}

/// `if (c) { x = A; } else { x = B; }` → `x = c ? A : B;`
pub fn ternary_fold(s: &mut Stmt) {
    let mut changed = true;
    let mut guard = 0;
    while changed && guard < 8 {
        changed = false;
        guard += 1;
        ternary_fold_walk(s, &mut changed);
        strip_empty(s);
    }
}

fn ternary_fold_walk(s: &mut Stmt, changed: &mut bool) {
    if let Stmt::Block(v) = s {
        for x in v.iter_mut() {
            ternary_fold_walk(x, changed);
        }
        return;
    }
    let Stmt::If {
        cond,
        then_stmt,
        else_stmt,
    } = s
    else {
        return;
    };
    ternary_fold_walk(then_stmt, changed);
    if let Some(e) = else_stmt {
        ternary_fold_walk(e, changed);
    }
    let Some(else_b) = else_stmt else { return };
    let target_of = |st: &Stmt| -> Option<u32> {
        let Stmt::ExprStmt(Expr::Assign { target, .. }) = st else {
            return None;
        };
        if let Expr::Local { var, .. } = &**target {
            Some(*var)
        } else {
            None
        }
    };
    let (Stmt::Block(tv), Stmt::Block(ev)) = (then_stmt.as_mut(), else_b.as_mut()) else {
        return;
    };
    if tv.len() != 1 || ev.len() != 1 {
        return;
    }
    let (Some(vt_), Some(ve)) = (target_of(&tv[0]), target_of(&ev[0])) else {
        return;
    };
    if vt_ != ve {
        return;
    }
    // The condition and both values must not re-assign the target between
    // the fold — they are single statements, so a mention is a re-read at
    // worst; re-assignment only happens via assignments inside them.
    let mut touched = HashSet::new();
    let (Stmt::ExprStmt(a_then), Stmt::ExprStmt(a_else)) = (&tv[0], &ev[0]) else {
        return;
    };
    if let Expr::Assign { value, .. } = a_then {
        collect_vars(value, &mut touched);
    }
    if let Expr::Assign { value, .. } = a_else {
        collect_vars(value, &mut touched);
    }
    if touched.contains(&vt_) {
        return;
    }
    let value_then = match a_then {
        Expr::Assign { value, .. } => value.clone(),
        _ => return,
    };
    let value_else = match a_else {
        Expr::Assign { value, .. } => value.clone(),
        _ => return,
    };
    let cond_e = cond.clone();
    let folded = Stmt::ExprStmt(Expr::Assign {
        target: Box::new(Expr::Local {
            var: vt_,
            ty: vt_join_ty(&value_then, &value_else),
        }),
        op: AssignOp::Plain,
        value: Box::new(Expr::Cond {
            c: Box::new(cond_e),
            t: value_then,
            f: value_else,
        }),
    });
    *s = Stmt::Block(vec![folded]);
    *changed = true;
}

fn vt_join_ty(a: &Expr, b: &Expr) -> TypeRef {
    let ta = a.type_ref();
    let tb = b.type_ref();
    if ta.erased() == tb.erased() {
        return ta;
    }
    TypeRef::J(JavaType::Object("java/lang/Object".into()))
}

/// Fold `new StringBuilder(...).append(x)...toString()` chains into
/// `StringConcat`. Single-assignment temporaries carry the chain.
///
/// d8 drops append results (statement-form calls), so a builder whose chain
/// has STATEMENT appends attached is left alone: folding its `toString`
/// with only the ctor arguments would misstate the contents.
pub fn fold_string_builders(s: &mut Stmt, vt: &VarTable) {
    // var → assigned value, for vars assigned exactly once.
    let n_vars = vt.vars.len().max(1);
    let mut counts = vec![0usize; n_vars];
    count_assignments(s, &mut counts);
    let mut values: Vec<Option<Expr>> = vec![None; n_vars];
    record_assignments(s, &counts, &mut values);

    // Builders with statement-form appends (their chains are incomplete).
    let mut appended_stmts: HashSet<u32> = HashSet::new();
    walk_all(s, &mut |st| {
        if let Stmt::ExprStmt(Expr::Method {
            cls,
            name,
            owner,
            args,
            ..
        }) = st
        {
            if name == "append" && is_string_builder(cls) && args.len() == 1 {
                if let Some(Expr::Local { var, .. }) = owner.as_deref() {
                    appended_stmts.insert(*var);
                }
            }
        }
    });

    rewrite_exprs(s, &mut |e| {
        fold_concat_in_expr(e, &values, &appended_stmts);
    });

    // Drop now-unused builder temporaries (their only consumers were
    // folded); the drop COUNT drives iteration — no statement counting
    // walks at all.
    for _ in 0..8 {
        let mut reads: HashSet<u32> = HashSet::new();
        stmt_collect_vars(s, &mut reads, false);
        if drop_unused_assigns(s, &reads) == 0 {
            break;
        }
    }
}

/// Deep statement count (pipeline guard input).
pub fn count_stmts_deep(s: &Stmt, out: &mut usize) {
    *out += 1;
    walk_all(s, &mut |_| {
        *out += 1;
    });
}

/// Fused per-variable analysis gathered in one statement-tree walk.
struct VarAnalysis {
    assigns: Vec<usize>,
    reads: Vec<usize>,
    /// Value of the (single) assignment, when recorded.
    values: Vec<Option<Expr>>,
}

fn analyze_vars(s: &Stmt, a: &mut VarAnalysis) {
    walk_all(s, &mut |st| {
        let exprs: Vec<&Expr> = match st {
            Stmt::ExprStmt(Expr::Assign { target, value, .. }) => {
                if let Expr::Local { var, .. } = &**target {
                    grow_to(&mut a.assigns, *var);
                    let idx = *var as usize;
                    a.assigns[idx] += 1;
                    if a.assigns[idx] == 1 {
                        if idx >= a.values.len() {
                            a.values.resize(idx + 1, None);
                        }
                        a.values[idx] = Some((**value).clone());
                    } else if idx < a.values.len() {
                        a.values[idx] = None;
                    }
                }
                let mut v: Vec<&Expr> = vec![value];
                if !matches!(&**target, Expr::Local { .. }) {
                    v.push(target);
                }
                v
            }
            Stmt::ExprStmt(e) | Stmt::Throw(e) | Stmt::MonitorEnter(e) | Stmt::MonitorExit(e) => {
                vec![e]
            }
            Stmt::Return(Some(e)) => vec![e],
            Stmt::LocalDef {
                var, init: Some(e), ..
            } => {
                grow_to(&mut a.assigns, *var);
                let idx = *var as usize;
                a.assigns[idx] += 1;
                if a.assigns[idx] == 1 {
                    if idx >= a.values.len() {
                        a.values.resize(idx + 1, None);
                    }
                    a.values[idx] = Some(e.clone());
                } else if idx < a.values.len() {
                    a.values[idx] = None;
                }
                vec![e]
            }
            Stmt::If { cond, .. } => vec![cond],
            Stmt::While { cond, .. } => vec![cond],
            Stmt::DoWhile { cond, .. } => vec![cond],
            _ => Vec::new(),
        };
        for e in exprs {
            visit_exprs(e, &mut |x| {
                if let Expr::Local { var, .. } = x {
                    grow_to(&mut a.reads, *var);
                    a.reads[*var as usize] += 1;
                }
            });
        }
    });
    // Keep the three views length-aligned.
    let n = a.assigns.len().max(a.reads.len()).max(a.values.len());
    a.assigns.resize(n, 0);
    a.reads.resize(n, 0);
    a.values.resize(n, None);
}

fn grow_to(v: &mut Vec<usize>, var: u32) {
    if var as usize >= v.len() {
        v.resize(var as usize + 1, 0);
    }
}

fn count_assignments(s: &Stmt, counts: &mut Vec<usize>) {
    walk_all(s, &mut |st| match st {
        Stmt::ExprStmt(Expr::Assign { target, .. }) => {
            if let Expr::Local { var, .. } = &**target {
                grow_to(counts, *var);
                counts[*var as usize] += 1;
            }
        }
        Stmt::LocalDef {
            var, init: Some(_), ..
        } => {
            grow_to(counts, *var);
            counts[*var as usize] += 1;
        }
        _ => {}
    });
}

fn record_assignments(s: &Stmt, counts: &[usize], out: &mut Vec<Option<Expr>>) {
    walk_all(s, &mut |st| match st {
        Stmt::ExprStmt(Expr::Assign { target, value, .. }) => {
            if let Expr::Local { var, .. } = &**target {
                if counts.get(*var as usize).copied().unwrap_or(0) == 1 {
                    if *var as usize >= out.len() {
                        out.resize(*var as usize + 1, None);
                    }
                    out[*var as usize] = Some((**value).clone());
                }
            }
        }
        Stmt::LocalDef {
            var, init: Some(e), ..
        } if counts.get(*var as usize).copied().unwrap_or(0) == 1 => {
            if *var as usize >= out.len() {
                out.resize(*var as usize + 1, None);
            }
            out[*var as usize] = Some(e.clone());
        }
        _ => {}
    });
}

fn fold_concat_in_expr(e: &mut Expr, values: &[Option<Expr>], appended: &HashSet<u32>) {
    deep_rewrite(e, &mut |x| {
        if let Expr::Method {
            cls,
            name,
            args,
            owner,
            ..
        } = x
        {
            if name == "toString" && args.is_empty() && is_string_builder(cls) {
                if let Some(o) = owner {
                    // Statement-form appends attached to any chain var mean
                    // the parts are incomplete — keep the call.
                    let mut has_stmt_appends = false;
                    visit_exprs(o, &mut |y| {
                        if let Expr::Local { var, .. } = y {
                            if appended.contains(var) {
                                has_stmt_appends = true;
                            }
                        }
                    });
                    if has_stmt_appends {
                        return;
                    }
                    let resolved = resolve_local(o, values);
                    if let Some(parts) = collect_sb_parts(&resolved, values, 0) {
                        *x = Expr::StringConcat(parts);
                    }
                }
            }
        }
    });
}

fn is_string_builder(cls: &str) -> bool {
    cls == "java/lang/StringBuilder" || cls == "java/lang/StringBuffer"
}

fn resolve_local(e: &Expr, values: &[Option<Expr>]) -> Expr {
    match e {
        Expr::Local { var, ty } => values
            .get(*var as usize)
            .and_then(|o| o.clone())
            .unwrap_or_else(|| Expr::Local {
                var: *var,
                ty: ty.clone(),
            }),
        other => other.clone(),
    }
}

/// Collect concat parts from a StringBuilder chain; depth caps cycles.
fn collect_sb_parts(e: &Expr, values: &[Option<Expr>], depth: u32) -> Option<Vec<ConcatPart>> {
    if depth > 16 {
        return None;
    }
    match e {
        Expr::Method {
            cls,
            name,
            args,
            owner,
            ..
        } if name == "append" && is_string_builder(cls) && args.len() == 1 => {
            let mut parts =
                collect_sb_parts(&resolve_local(owner.as_deref()?, values), values, depth + 1)?;
            parts.push(ConcatPart::Str(args[0].clone()));
            Some(parts)
        }
        Expr::New {
            cls,
            args,
            raw: false,
            ..
        } if is_string_builder(cls) => {
            let mut parts = Vec::new();
            for a in args {
                if let Expr::Const(ConstVal::Str(sv)) = a {
                    parts.push(ConcatPart::Const(sv.clone()));
                } else {
                    parts.push(ConcatPart::Str(a.clone()));
                }
            }
            Some(parts)
        }
        _ => None,
    }
}

fn drop_unused_assigns(s: &mut Stmt, reads: &HashSet<u32>) -> usize {
    let mut dropped = 0usize;
    walk_mut_deep(s, &mut |st| {
        if let Stmt::Block(v) = st {
            let before = v.len();
            v.retain(|x| match x {
                // Drop only when unread AND a builder chain (folded
                // consumer; `new StringBuilder` chains cannot NPE).
                Stmt::ExprStmt(Expr::Assign { target, value, .. }) => match &**target {
                    Expr::Local { var, .. } => reads.contains(var) || !is_sbish(value),
                    _ => true,
                },
                Stmt::LocalDef { var, init, .. } => {
                    reads.contains(var) || !init.as_ref().map(is_sbish).unwrap_or(false)
                }
                _ => true,
            });
            dropped += before - v.len();
        }
    });
    dropped
}

fn is_sbish(e: &Expr) -> bool {
    match e {
        Expr::New {
            cls, raw: false, ..
        } => is_string_builder(cls),
        Expr::Method { name, cls, .. } => name == "append" && is_string_builder(cls),
        _ => false,
    }
}

fn walk_mut_deep<F: FnMut(&mut Stmt)>(s: &mut Stmt, f: &mut F) {
    f(s);
    walk_mut(s, &mut |x| walk_mut_deep(x, f));
}

/// Recover `synchronized` from the d8 monitor pattern:
/// `monitorenter(e); try { body } catch (Throwable) { monitorexit(e); throw t; }`
/// (optionally followed by `monitorexit(e)`).
pub fn fold_synchronized(s: &mut Stmt) {
    fold_sync_walk(s);
}

fn fold_sync_walk(s: &mut Stmt) {
    walk_mut_deep(s, &mut |st| {
        let Stmt::Block(v) = st else { return };
        let mut i = 0;
        while i < v.len() {
            if i + 1 < v.len() {
                if let Some(sync) = try_sync_at(v, i) {
                    let _ = v.drain(i..i + 2);
                    v.insert(i, sync);
                    continue;
                }
            }
            i += 1;
        }
    });
}

fn try_sync_at(v: &[Stmt], i: usize) -> Option<Stmt> {
    let Stmt::MonitorEnter(lock) = &v[i] else {
        return None;
    };
    let Stmt::Try {
        body,
        catches,
        finally,
    } = &v[i + 1]
    else {
        return None;
    };
    if finally.is_some() || catches.len() != 1 {
        return None;
    }
    let c = &catches[0];
    if !c.exc.is_empty() {
        return None;
    }
    // The catch-all body: monitorexit(lock) then rethrow.
    let Stmt::Block(cv) = c.body.as_ref() else {
        return None;
    };
    let exit_matches = cv.len() >= 2
        && matches!(&cv[0], Stmt::MonitorExit(e) if expr_local_var(e) == expr_local_var(lock));
    let throws = cv.len() >= 2 && matches!(&cv[1], Stmt::Throw(_));
    if !(exit_matches && throws) {
        return None;
    }
    Some(Stmt::Synchronized {
        lock: lock.clone(),
        body: body.clone(),
    })
}

fn expr_local_var(e: &Expr) -> Option<u32> {
    if let Expr::Local { var, .. } = e {
        Some(*var)
    } else {
        None
    }
}

/// Copy-forward single-use temporaries: `v = e; ... v ...` inlines `e` at
/// the (single) use and drops the assignment when safe. Pure values inline
/// anywhere; impure values (calls, array reads) only when the use is the
/// statement immediately after the definition.
pub fn forward_single_use(s: &mut Stmt, _vt: &VarTable) {
    // Fused single traversal: assignment counts, read counts and the
    // single-assignment values all come out of ONE walk (three separate
    // full-tree walks dominated the pass cost on large methods).
    let mut analysis = VarAnalysis {
        assigns: Vec::new(),
        reads: Vec::new(),
        values: Vec::new(),
    };
    analyze_vars(s, &mut analysis);
    let mut assigns = analysis.assigns;
    let mut reads = analysis.reads;
    // Var ids beyond the table (synthetic test shapes) are covered by the
    // counters' on-demand growth.
    let n_vars = assigns.len().max(_vt.vars.len()).max(1);
    assigns.resize(n_vars, 0);
    reads.resize(n_vars, 0);
    let mut values = analysis.values;
    values.resize(n_vars, None);

    // Candidates: assigned exactly once, read exactly once. Additionally
    // the inlined VALUE must not reference a multi-assigned var (phi vars):
    // moving the read across the phi's reassignment would be a stale
    // capture (register rotations snapshot through temps for this reason).
    let mut single = vec![false; n_vars];
    for (v, single_v) in single.iter_mut().enumerate() {
        if assigns.get(v).copied().unwrap_or(0) != 1 || reads.get(v).copied().unwrap_or(0) != 1 {
            continue;
        }
        if let Some(val) = values.get(v).and_then(|o| o.as_ref()) {
            let mut refs = HashSet::new();
            collect_vars(val, &mut refs);
            if refs.iter().any(|r| assigns[*r as usize] > 1) {
                continue;
            }
        }
        *single_v = true;
    }
    if !single.iter().any(|&b| b) {
        return;
    }
    let pure: Vec<bool> = (0..n_vars)
        .map(|v| {
            single[v]
                && values
                    .get(v)
                    .and_then(|o| o.as_ref())
                    .map(|e| !has_side_effects(e))
                    .unwrap_or(false)
        })
        .collect();
    let impure: Vec<bool> = (0..n_vars).map(|v| single[v] && !pure[v]).collect();

    // 1. Pure values: inline anywhere.
    if pure.iter().any(|&b| b) {
        let vals: Vec<Option<Expr>> = (0..n_vars)
            .map(|v| {
                if pure[v] {
                    values.get(v).cloned().flatten()
                } else {
                    None
                }
            })
            .collect();
        rewrite_exprs(s, &mut |e| {
            deep_rewrite(e, &mut |x| {
                if let Expr::Local { var, .. } = x {
                    if let Some(Some(v)) = vals.get(*var as usize) {
                        *x = v.clone();
                    }
                }
            });
        });
        drop_defs(s, &pure);
    }

    // 2. Impure values: inline only into the immediately following
    //    statement.
    if impure.iter().any(|&b| b) {
        forward_adjacent_impure(s, &values, &impure);
    }
}

/// Count READS of variables (assignment targets excluded).
fn count_reads(s: &Stmt, out: &mut Vec<usize>) {
    walk_all(s, &mut |st| {
        let exprs: Vec<&Expr> = match st {
            // Assign must match BEFORE the generic ExprStmt arm (the
            // assignment target is a write, not a read).
            Stmt::ExprStmt(Expr::Assign { target, value, .. }) => {
                let mut v: Vec<&Expr> = vec![value];
                if !matches!(&**target, Expr::Local { .. }) {
                    v.push(target);
                }
                v
            }
            Stmt::ExprStmt(e) | Stmt::Throw(e) | Stmt::MonitorEnter(e) | Stmt::MonitorExit(e) => {
                vec![e]
            }
            Stmt::Return(Some(e)) => vec![e],
            Stmt::LocalDef { init: Some(e), .. } => vec![e],
            Stmt::If { cond, .. } => vec![cond],
            Stmt::While { cond, .. } => vec![cond],
            Stmt::DoWhile { cond, .. } => vec![cond],
            _ => Vec::new(),
        };
        for e in exprs {
            visit_exprs(e, &mut |x| {
                if let Expr::Local { var, .. } = x {
                    grow_to(out, *var);
                    out[*var as usize] += 1;
                }
            });
        }
    });
}

fn drop_defs(s: &mut Stmt, vars: &[bool]) {
    walk_mut_deep(s, &mut |st| {
        if let Stmt::Block(v) = st {
            v.retain(|x| match x {
                Stmt::ExprStmt(Expr::Assign { target, .. }) => match &**target {
                    Expr::Local { var, .. } => !vars.get(*var as usize).copied().unwrap_or(false),
                    _ => true,
                },
                Stmt::LocalDef { var, .. } => !vars.get(*var as usize).copied().unwrap_or(false),
                _ => true,
            });
        }
    });
}

/// For each statement list: `v = IMPURE; NEXT(v)` folds NEXT's reference.
fn forward_adjacent_impure(s: &mut Stmt, values: &[Option<Expr>], impure: &[bool]) {
    if let Stmt::Block(v) = s {
        let mut i = 0;
        while i + 1 < v.len() {
            let def_var = match &v[i] {
                Stmt::ExprStmt(Expr::Assign { target, .. }) => match &**target {
                    Expr::Local { var, .. } => Some(*var),
                    _ => None,
                },
                Stmt::LocalDef { var, .. } => Some(*var),
                _ => None,
            };
            if let Some(var) = def_var {
                if impure.get(var as usize).copied().unwrap_or(false) {
                    // Does the NEXT statement reference var?
                    let mut reads_here = vec![0usize; values.len().max(1)];
                    count_reads(&v[i + 1], &mut reads_here);
                    if reads_here.get(var as usize).copied().unwrap_or(0) == 1 {
                        // The def statement's CURRENT value (earlier inlines
                        // in this walk may have rewritten it — the pre-built
                        // values map would be stale).
                        let val = match &v[i] {
                            Stmt::ExprStmt(Expr::Assign { value, .. }) => (**value).clone(),
                            Stmt::LocalDef { init: Some(e), .. } => (*e).clone(),
                            _ => {
                                i += 1;
                                continue;
                            }
                        };
                        rewrite_exprs(&mut v[i + 1], &mut |e| {
                            deep_rewrite(e, &mut |x| {
                                if let Expr::Local { var: v2, .. } = x {
                                    if *v2 == var {
                                        *x = val.clone();
                                    }
                                }
                            });
                        });
                        v.remove(i);
                        // The PREVIOUS definition may now be adjacent to its
                        // (shifted) use — re-examine it.
                        i = i.saturating_sub(1);
                        continue;
                    }
                }
            }
            i += 1;
        }
    }
    walk_mut(s, &mut |x| forward_adjacent_impure(x, values, impure));
}

// ---------------------------------------------------------------------------
// Type inference, booleanization, null comparisons, declarations
// ---------------------------------------------------------------------------

/// Evidence-based type inference for synthetic (non-parameter) vars.
pub fn infer_types(vt: &mut VarTable, body: &mut Stmt, ret: &JavaType, env: &MethodEnv) {
    let n_vars = vt.vars.len();
    let mut evidence: Vec<Vec<JavaType>> = vec![Vec::new(); n_vars];
    let ev = |evidence: &mut Vec<Vec<JavaType>>, var: u32, t: JavaType| {
        if (var as usize) < evidence.len() {
            evidence[var as usize].push(t);
        }
    };

    walk_all(body, &mut |st| match st {
        Stmt::LocalDef { var, init, .. } => {
            if let Some(e) = init {
                expr_evidence(e, &mut |v, t| ev(&mut evidence, v, t));
                if let Expr::Local { var: src, .. } = e {
                    let _ = src;
                }
                if let Expr::Local { var: src, .. } = e {
                    if evidence.get(*var as usize).is_some() {
                        let _ = src;
                    }
                }
            }
        }
        Stmt::ExprStmt(e) => expr_evidence(e, &mut |v, t| ev(&mut evidence, v, t)),
        Stmt::Throw(e) => {
            expr_evidence(e, &mut |v, t| ev(&mut evidence, v, t));
            if let Expr::Local { var, .. } = e {
                ev(
                    &mut evidence,
                    *var,
                    JavaType::Object("java/lang/Throwable".into()),
                );
            }
        }
        Stmt::Return(Some(e)) => {
            expr_evidence(e, &mut |v, t| ev(&mut evidence, v, t));
            if let Expr::Local { var, .. } = e {
                ev(&mut evidence, *var, ret.clone());
            }
        }
        Stmt::MonitorEnter(e) | Stmt::MonitorExit(e) => {
            if let Expr::Local { var, .. } = e {
                ev(
                    &mut evidence,
                    *var,
                    JavaType::Object("java/lang/Object".into()),
                );
            }
        }
        Stmt::ForEach {
            var,
            iterable,
            is_array,
            ..
        } => {
            if let Expr::Local { var: v0, .. } = iterable {
                if *is_array {
                    ev(&mut evidence, *v0, JavaType::Array(Box::new(JavaType::Int)));
                } else {
                    ev(
                        &mut evidence,
                        *v0,
                        JavaType::Object("java/lang/Object".into()),
                    );
                }
            }
            let _ = var;
        }
        _ => {}
    });
    let _ = env;

    // Return-position locals take the declared return type (also inside
    // nested returns — handled by the walk above).

    for (i, evs) in evidence.iter_mut().enumerate() {
        let info = &vt.vars[i];
        if info.is_param {
            continue;
        }
        if info.ty.erased().is_reference() {
            // Only refine reference-typed synthetics with object evidence.
            if let Some(t) = pick_object(evs) {
                vt.vars[i].ty = TypeRef::J(t);
            }
        } else if evs.iter().all(|t| t.is_numeric()) && !evs.is_empty() {
            if let Some(t) = pick_numeric(evs) {
                if !info.ty.erased().is_reference() {
                    vt.vars[i].ty = TypeRef::J(t);
                }
            }
        } else if let Some(t) = pick_object(evs) {
            vt.vars[i].ty = TypeRef::J(t);
        }
    }

    // Rewrite embedded Local types.
    let types: Vec<TypeRef> = vt.vars.iter().map(|v| v.ty.clone()).collect();
    rewrite_exprs(body, &mut |e| {
        deep_rewrite(e, &mut |x| {
            if let Expr::Local { var, ty } = x {
                if (*var as usize) < types.len() {
                    *ty = types[*var as usize].clone();
                }
            }
        });
    });

    // Numeric literals take their variable's declared width (`double v = 0L`
    // prints as `0.0`; `int x = 5L` as `5`).
    coerce_num_consts(body, &types);
}

fn coerce_num_consts(body: &mut Stmt, types: &[TypeRef]) {
    walk_mut_deep(body, &mut |st| {
        let (var, val): (u32, &mut Expr) = match st {
            Stmt::ExprStmt(Expr::Assign { target, value, .. }) => match &mut **target {
                Expr::Local { var, .. } => (*var, value),
                _ => return,
            },
            Stmt::LocalDef {
                var, init: Some(e), ..
            } => (*var, e),
            _ => return,
        };
        let want = match types.get(var as usize) {
            Some(TypeRef::J(t)) => t.clone(),
            _ => return,
        };
        let rewritten = match &*val {
            Expr::Const(ConstVal::Long(l)) => match &want {
                JavaType::Double => Some(Expr::Const(ConstVal::Double(*l as f64))),
                JavaType::Float => Some(Expr::Const(ConstVal::Float(*l as f32))),
                _ => None,
            },
            Expr::Const(ConstVal::Int(i)) => match &want {
                JavaType::Double => Some(Expr::Const(ConstVal::Double(*i as f64))),
                JavaType::Float => Some(Expr::Const(ConstVal::Float(*i as f32))),
                _ => None,
            },
            _ => None,
        };
        if let Some(e) = rewritten {
            *val = e;
        }
    });
}

fn pick_object(evs: &[JavaType]) -> Option<JavaType> {
    evs.iter()
        .find(|t| t.is_reference() && !matches!(t, JavaType::Object(n) if n == "java/lang/Object"))
        .cloned()
}

fn pick_numeric(evs: &[JavaType]) -> Option<JavaType> {
    if evs.is_empty() {
        return None;
    }
    let mut t = evs[0].clone();
    for x in &evs[1..] {
        t = join_numeric(&t, x);
    }
    Some(t)
}

fn join_numeric(a: &JavaType, b: &JavaType) -> JavaType {
    if a == b {
        return a.clone();
    }
    match (a, b) {
        (JavaType::Double, _) | (_, JavaType::Double) => JavaType::Double,
        (JavaType::Float, _) | (_, JavaType::Float) => JavaType::Float,
        (JavaType::Long, _) | (_, JavaType::Long) => JavaType::Long,
        (JavaType::Int, x) if x.is_integral() => JavaType::Int,
        (x, JavaType::Int) if x.is_integral() => JavaType::Int,
        (x, y) if x.is_integral() && y.is_integral() => JavaType::Int,
        _ => JavaType::Int,
    }
}

/// Gather per-var type evidence from one expression.
fn expr_evidence<F: FnMut(u32, JavaType)>(e: &Expr, f: &mut F) {
    visit_exprs(e, &mut |x| match x {
        Expr::Method {
            owner,
            args,
            desc,
            is_static,
            cls,
            ..
        } => {
            if !*is_static {
                if let Some(o) = owner {
                    if let Expr::Local { var, .. } = &**o {
                        f(*var, JavaType::Object(cls.clone()));
                    }
                }
            }
            for (i, a) in args.iter().enumerate() {
                if let Expr::Local { var, .. } = a {
                    if let Some(t) = desc.args.get(i) {
                        f(*var, t.clone());
                    }
                }
            }
        }
        Expr::Field {
            owner,
            ty,
            is_static,
            ..
        } => {
            if !*is_static {
                if let Some(o) = owner {
                    if let Expr::Local { var, .. } = &**o {
                        f(*var, JavaType::Object("java/lang/Object".into()));
                    }
                }
            }
            let _ = ty;
        }
        Expr::ArrayIndex { array, .. } => {
            if let Expr::Local { var, ty, .. } = &**array {
                // Reinforce the local's KNOWN array type: the hardcoded
                // int[] fallback contradicted a typed array local (a
                // register reused for byte[], int[] then byte[] across
                // one clinit labeled the byte[] defs `int[]`).
                let t = ty.erased();
                if matches!(t, JavaType::Array(_)) {
                    f(*var, t);
                } else {
                    f(*var, JavaType::Array(Box::new(JavaType::Int)));
                }
            }
        }
        Expr::Assign { target, value, .. } => {
            if let Expr::Local { var, .. } = &**target {
                f(*var, value.type_ref().erased());
            }
        }
        Expr::Cast { ty, e: inner } => {
            if let Expr::Local { var, .. } = &**inner {
                f(*var, ty.erased());
            }
        }
        Expr::InstanceOf { e: inner, .. } => {
            let _ = inner;
        }
        _ => {}
    });
}

/// Boolean inference: vars only ever assigned 0/1/comparisons/booleans and
/// read in conditions become `boolean`, with `v != 0` → `v` in conditions.
pub fn booleanize(vt: &mut VarTable, body: &mut Stmt) {
    let n = vt.vars.len();
    let mut in_cond = vec![false; n];

    // Condition uses: `v == 0` / `v != 0` if-conditions and comparison
    // operands inside assigned values.
    walk_all(body, &mut |st| {
        let cond: Option<&Expr> = match st {
            Stmt::If { cond, .. } | Stmt::While { cond, .. } | Stmt::DoWhile { cond, .. } => {
                Some(cond)
            }
            _ => None,
        };
        if let Some(c) = cond {
            if let Expr::Bin {
                op: BinOp::Eq | BinOp::Ne,
                l,
                r,
                ..
            } = c
            {
                for (x, other) in [(l, r), (r, l)] {
                    if let (Expr::Local { var, .. }, Expr::Const(ConstVal::Int(0))) =
                        (&**x, &**other)
                    {
                        if (*var as usize) < n {
                            in_cond[*var as usize] = true;
                        }
                    }
                }
            }
        }
        let val: Option<&Expr> = match st {
            Stmt::ExprStmt(Expr::Assign { value, .. }) => Some(value),
            Stmt::LocalDef { init: Some(e), .. } => Some(e),
            Stmt::Return(Some(e)) => Some(e),
            _ => None,
        };
        if let Some(v) = val {
            visit_exprs(v, &mut |x| {
                if let Expr::Bin { op, l, r, .. } = x {
                    if matches!(
                        op,
                        BinOp::Eq | BinOp::Ne | BinOp::Lt | BinOp::Ge | BinOp::Gt | BinOp::Le
                    ) {
                        for side in [l, r] {
                            if let Expr::Local { var, .. } = &**side {
                                if (*var as usize) < n {
                                    in_cond[*var as usize] = true;
                                }
                            }
                        }
                    }
                }
            });
        }
    });

    // A var whose every assignment value is boolean-shaped AND which is
    // referenced in conditions becomes boolean.
    // (Perf: this used to re-walk the whole statement tree ONCE PER VAR —
    // O(vars × stmts); on R8-merged monsters (2000+ vars, 15k statements)
    // that was tens of millions of visits. One pass collects the same
    // (any, all_bool) facts for every var.)
    let mut assigned_any = vec![false; n];
    let mut all_bool = vec![true; n];
    walk_all(body, &mut |st| {
        let (var, value) = match st {
            Stmt::ExprStmt(Expr::Assign { target, value, .. }) => match &**target {
                Expr::Local { var, .. } => (var, &**value),
                _ => return,
            },
            Stmt::LocalDef {
                var, init: Some(e), ..
            } => (var, e),
            _ => return,
        };
        let i = *var as usize;
        if i < n {
            assigned_any[i] = true;
            if !is_boolean_valued(value) {
                all_bool[i] = false;
            }
        }
    });
    let mut boolean_vars: HashSet<u32> = HashSet::new();
    for i in 0..n {
        if vt.vars[i].is_param {
            continue;
        }
        if !in_cond[i] {
            continue;
        }
        if assigned_any[i] && all_bool[i] {
            boolean_vars.insert(i as u32);
        }
    }
    if boolean_vars.is_empty() {
        return;
    }
    for v in &boolean_vars {
        vt.vars[*v as usize].ty = TypeRef::J(JavaType::Boolean);
    }
    let types: Vec<TypeRef> = vt.vars.iter().map(|v| v.ty.clone()).collect();
    rewrite_exprs(body, &mut |e| {
        deep_rewrite(e, &mut |x| {
            if let Expr::Local { var, ty } = x {
                if (*var as usize) < types.len() {
                    *ty = types[*var as usize].clone();
                }
            }
        });
    });

    // Condition folding: `b != 0` → `b`, `b == 0` → `!b` (boolean vars).
    fold_bool_conditions(body, &boolean_vars);
}

fn is_boolean_valued(e: &Expr) -> bool {
    match e {
        Expr::Const(ConstVal::Int(0)) | Expr::Const(ConstVal::Int(1)) => true,
        Expr::Bin { op, .. } => matches!(
            op,
            BinOp::Eq | BinOp::Ne | BinOp::Lt | BinOp::Ge | BinOp::Gt | BinOp::Le
        ),
        Expr::InstanceOf { .. } => true,
        Expr::Local { ty, .. } => ty.erased() == JavaType::Boolean,
        Expr::Method { desc, .. } => desc.ret == JavaType::Boolean,
        Expr::Cond { t, f, .. } => is_boolean_valued(t) && is_boolean_valued(f),
        Expr::Un { op: UnOp::Not, .. } => true,
        _ => false,
    }
}

fn fold_bool_conditions(s: &mut Stmt, bv: &HashSet<u32>) {
    let fold = |e: &mut Expr| {
        deep_rewrite(e, &mut |x| {
            if let Expr::Bin { op, l, r, .. } = x {
                let (var_side, const_side) = match (&**l, &**r) {
                    (Expr::Local { .. }, Expr::Const(ConstVal::Int(_))) => (l, 0),
                    (Expr::Const(ConstVal::Int(_)), Expr::Local { .. }) => (r, 1),
                    _ => return,
                };
                let var = match &**var_side {
                    Expr::Local { var, .. } => *var,
                    _ => return,
                };
                if !bv.contains(&var) {
                    return;
                }
                let _ = const_side;
                match op {
                    BinOp::Ne => {
                        let inner = var_side.clone();
                        *x = *inner;
                    }
                    BinOp::Eq => {
                        let inner = var_side.clone();
                        *x = Expr::Un {
                            op: UnOp::Not,
                            e: Box::new(*inner),
                        };
                    }
                    _ => {}
                }
            }
        });
    };
    match s {
        Stmt::If { cond, .. } | Stmt::While { cond, .. } | Stmt::DoWhile { cond, .. } => fold(cond),
        _ => {}
    }
    walk_mut_deep(s, &mut |st| {
        let cond = match st {
            Stmt::If { cond, .. } => Some(cond),
            Stmt::While { cond, .. } => Some(cond),
            Stmt::DoWhile { cond, .. } => Some(cond),
            _ => None,
        };
        if let Some(c) = cond {
            fold(c);
        }
    });
}

/// Normalize `1 == v` comparisons to `v == 1` (d8 emits const-first if-eq).
pub fn flip_const_compares(s: &mut Stmt) {
    rewrite_exprs(s, &mut |e| {
        deep_rewrite(e, &mut |x| {
            if let Expr::Bin { op, l, r, .. } = x {
                if matches!(
                    op,
                    BinOp::Eq | BinOp::Ne | BinOp::Lt | BinOp::Ge | BinOp::Gt | BinOp::Le
                ) {
                    let l_const = matches!(&**l, Expr::Const(_));
                    let r_var = matches!(&**r, Expr::Local { .. });
                    if l_const && r_var {
                        std::mem::swap(l, r);
                    }
                }
            }
        });
    });
}

/// Object-typed locals compared against 0 compare against `null`.
pub fn null_compares(vt: &VarTable, body: &mut Stmt) {
    let obj_vars: HashSet<u32> = vt
        .vars
        .iter()
        .filter(|v| v.ty.erased().is_reference())
        .map(|v| v.id)
        .collect();
    if obj_vars.is_empty() {
        return;
    }
    rewrite_exprs(body, &mut |e| {
        deep_rewrite(e, &mut |x| {
            if let Expr::Bin { op, l, r, .. } = x {
                if !matches!(op, BinOp::Eq | BinOp::Ne) {
                    return;
                }
                let rewrite = |side: &mut Expr, other: &Expr| {
                    if let Expr::Const(ConstVal::Int(0)) = other {
                        if let Expr::Local { var, .. } = &*side {
                            if obj_vars.contains(var) {
                                *side = Expr::Const(ConstVal::Null);
                            }
                        }
                    }
                };
                let lo = l.clone();
                let ro = r.clone();
                rewrite(l, &ro);
                rewrite(r, &lo);
            }
        });
    });
}

/// Declaration hygiene: every used var that has no LocalDef gets a bare
/// declaration at the top; duplicate LocalDefs demote to assignments.
pub fn ensure_declared(body: &mut Stmt, vt: &VarTable) {
    // (Perf: dense Vec<bool> tables instead of HashSets — var ids are
    // dense; the `assigned` set collected here was never read and cost a
    // full extra tree walk per method.)
    let n = vt.vars.len().max(1);
    let mut declared: Vec<bool> = vec![false; n];
    let mut is_param: Vec<bool> = vec![false; n];
    for v in &vt.vars {
        if v.is_param && (v.id as usize) < n {
            is_param[v.id as usize] = true;
        }
    }
    walk_all(body, &mut |st| {
        if let Stmt::LocalDef { var, .. } = st {
            if (*var as usize) < n {
                declared[*var as usize] = true;
            }
        }
    });
    let mut used: HashSet<u32> = HashSet::new();
    stmt_collect_vars(body, &mut used, false);

    // Params are declared by the signature.
    let mut needs_decl: Vec<u32> = used
        .into_iter()
        .filter(|v| {
            let i = *v as usize;
            i >= n || (!declared[i] && !is_param[i])
        })
        .collect();
    needs_decl.sort_unstable();

    // Demote extra LocalDefs (same var declared more than once). A fresh
    // set: the pre-collected `declared` would demote every def.
    let mut seen: HashSet<u32> = HashSet::new();
    demote_dup_decls(body, &mut seen, vt);

    if !needs_decl.is_empty() {
        let mut decls: Vec<Stmt> = needs_decl
            .into_iter()
            .map(|v| Stmt::LocalDef {
                var: v,
                init: None,
                is_final: false,
                force_type: true,
            })
            .collect();
        decls.reverse();
        match body {
            Stmt::Block(v) => {
                for d in decls {
                    v.insert(0, d);
                }
            }
            other => {
                let inner = std::mem::replace(other, Stmt::Block(vec![]));
                *other = Stmt::Block({
                    let mut vs = decls;
                    vs.push(inner);
                    vs
                });
            }
        }
    }
}

fn demote_dup_decls(s: &mut Stmt, seen: &mut HashSet<u32>, vt: &VarTable) {
    match s {
        // Exactly one visit per node: the Block arm consumes its children,
        // the fallthrough walk would double-visit them.
        Stmt::Block(v) => {
            for x in v.iter_mut() {
                demote_dup_decls(x, seen, vt);
            }
        }
        Stmt::LocalDef { var, init, .. } => {
            if seen.contains(var) {
                let ty = vt.var(*var).ty.clone();
                if let Some(e) = init.take() {
                    *s = Stmt::ExprStmt(Expr::Assign {
                        target: Box::new(Expr::Local { var: *var, ty }),
                        op: AssignOp::Plain,
                        value: Box::new(e),
                    });
                } else {
                    *s = Stmt::Block(vec![]);
                }
            } else {
                seen.insert(*var);
            }
        }
        other => {
            walk_mut(other, &mut |x| demote_dup_decls(x, seen, vt));
        }
    }
}

#[allow(dead_code)]
fn unused(_: &Vec<CaseGroup>, _: &Catch) {}
