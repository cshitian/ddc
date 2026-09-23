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

use jdc_core::FxHashSet as HashSet;

// The tree-walker match arms intentionally mirror the statement grammar
// one level at a time; collapsing the nested `if let`s into outer match
// arms would trade per-arm clarity for lint silence.
use jdc_core::ir::build::has_side_effects;
use jdc_core::emit::is_java_keyword;
use jdc_core::ir::expr::{AssignOp, BinOp, ConcatPart, ConstVal, Expr, TypeRef, UnOp};
use jdc_core::ir::stmt::{CaseGroup, Catch, Stmt};
use jdc_core::types::{JavaType, MethodDescriptor};
use jdc_core::var::VarTable;

use crate::lift::MethodEnv;
use crate::{access, desc_type, DexPool};
use ddc_dex::insn::{Insn, InsnKind, InvokeKind};
use jdc_core::types::parse_method_descriptor;

// ---------------------------------------------------------------------------
// Generic tree walking
// ---------------------------------------------------------------------------

/// Deep expression rewrite over a statement tree.
pub fn rewrite_exprs<F: FnMut(&mut Expr)>(s: &mut Stmt, f: &mut F) {
    walk_stmt_exprs(s, f);
}

pub(crate) fn walk_stmt_exprs<F: FnMut(&mut Expr)>(s: &mut Stmt, f: &mut F) {
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
pub(crate) fn deep_rewrite<F: FnMut(&mut Expr)>(e: &mut Expr, f: &mut F) {
    f(e);
    for_each_child_mut(e, &mut |c| deep_rewrite(c, f));
}

/// `deep_rewrite` that respects WRITE positions: a `Local` appearing as
/// an assignment target or a `++`/`--` operand never reaches `f`.
/// Value-forwarding closures (`*x = value`) must use this — plain
/// deep_rewrite turned a forwarded `vX = 25` into `25 = 25` (target
/// replaced, and drop_defs then no longer recognized the statement, so
/// the garbage survived into the output; reqable a4/e). Compound
/// targets (`a[i] = …`, `o.f = …`) still recurse: owners and indices
/// ARE reads.
fn deep_rewrite_reads<F: FnMut(&mut Expr)>(e: &mut Expr, f: &mut F) {
    f(e);
    match e {
        Expr::Assign { target, value, .. } => {
            if !matches!(**target, Expr::Local { .. }) {
                deep_rewrite_reads(target, f);
            }
            deep_rewrite_reads(value, f);
        }
        Expr::PreIncDec { e: inner, .. } | Expr::PostIncDec { e: inner, .. } => {
            if !matches!(**inner, Expr::Local { .. }) {
                deep_rewrite_reads(inner, f);
            }
        }
        _ => for_each_child_mut(e, &mut |c| deep_rewrite_reads(c, f)),
    }
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
    // Vars defined anywhere in the method (params + LocalDefs +
    // assign targets): a catch body reading a var OUTSIDE this set is
    // the unmaterialized move-exception register (the lifter minted it
    // without a defining statement).
    let mut defined: jdc_core::FxHashSet<u32> = jdc_core::FxHashSet::default();
    for v in &vt.vars {
        if v.is_param {
            defined.insert(v.id);
        }
    }
    collect_defined_locals(s, &mut defined);
    let reads_all = count_locals_stmts(std::slice::from_ref(s));
    // Vars with a real assignment (LocalDef-with-init or assign target):
    // a var only ever READ is either the unmaterialized move-exception
    // register or a bare declaration awaiting its hoisted assignment.
    let mut assigned: jdc_core::FxHashSet<u32> = jdc_core::FxHashSet::default();
    collect_assigned_locals(s, &mut assigned);
    let mut fallback_bound: Vec<u32> = Vec::new();
    bind_catches_walk(s, vt, &defined, &reads_all, &assigned, &mut fallback_bound);
    // The catch parameter IS the declaration now: drop the bare
    // `Throwable th;` hoists for vars the fallback bound.
    if !fallback_bound.is_empty() {
        remove_bare_decls(s, &fallback_bound);
    }
}

fn collect_defined_locals(s: &Stmt, out: &mut jdc_core::FxHashSet<u32>) {
    crate::passes::walk_all(s, &mut |st| {
        match st {
            Stmt::LocalDef { var, .. } => {
                out.insert(*var);
            }
            Stmt::ExprStmt(Expr::Assign { target, .. }) => {
                if let Expr::Local { var, .. } = &**target {
                    out.insert(*var);
                }
            }
            _ => {}
        }
    });
}


/// First read of a local that is defined nowhere in the method (and is
/// not a parameter) inside the catch body — the unmaterialized
/// move-exception register.
/// Vars carrying a real assignment (init or write target).
fn collect_assigned_locals(s: &Stmt, out: &mut jdc_core::FxHashSet<u32>) {
    crate::passes::walk_all(s, &mut |st| {
        match st {
            Stmt::LocalDef { var, init: Some(_), .. } => {
                out.insert(*var);
            }
            Stmt::ExprStmt(Expr::Assign { target, .. }) => {
                if let Expr::Local { var, .. } = &**target {
                    out.insert(*var);
                }
            }
            _ => {}
        }
    });
}

/// First `throw <local>` var in the catch body that is never assigned
/// anywhere and is exception-typed — the unmaterialized move-exception.
fn first_thrown_unassigned_local(
    body: &Stmt,
    vt: &VarTable,
    assigned: &jdc_core::FxHashSet<u32>,
) -> Option<u32> {
    let mut found: Option<u32> = None;
    let c = body.clone();
    walk_all(&c, &mut |st| {
        if let Stmt::Throw(th) = st {
            if let Expr::Local { var, .. } = th {
                let v = *var;
                if !assigned.contains(&v) {
                    if let JavaType::Object(o) = vt.var(v).ty.erased() {
                        if o.as_ref() == "java/lang/Throwable" {
                            found = Some(v);
                        }
                    }
                }
            }
        }
    });
    found
}

/// Remove bare `LocalDef{var, init: None}` declarations for the given
/// vars (the catch parameter is their declaration now).
fn remove_bare_decls(s: &mut Stmt, vars: &[u32]) {
    let vars: jdc_core::FxHashSet<u32> = vars.iter().copied().collect();
    walk_mut_deep(s, &mut |st| {
        if let Stmt::Block(v) = st {
            v.retain(|x| {
                !matches!(x, Stmt::LocalDef { var, init: None, .. } if vars.contains(var))
            });
        }
    });
}

fn first_undefined_local_read(
    body: &Stmt,
    defined: &jdc_core::FxHashSet<u32>,
) -> Option<u32> {
    let mut found: Option<u32> = None;
    let mut c = body.clone();
    crate::passes::walk_stmt_exprs(&mut c, &mut |e| {
        if found.is_none() {
            deep_rewrite(e, &mut |x| {
                if found.is_none() {
                    if let Expr::Local { var, .. } = x {
                        if !defined.contains(var) {
                            found = Some(*var);
                        }
                    }
                }
            });
        }
    });
    found
}

#[allow(clippy::too_many_arguments)]
fn bind_catches_walk(
    s: &mut Stmt,
    vt: &mut VarTable,
    defined: &jdc_core::FxHashSet<u32>,
    reads_all: &std::collections::HashMap<u32, usize>,
    assigned: &jdc_core::FxHashSet<u32>,
    fallback_bound: &mut Vec<u32>,
) {
    match s {
        Stmt::Try {
            body,
            catches,
            finally,
        } => {
            bind_catches_walk(body, vt, defined, reads_all, assigned, fallback_bound);
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
                    } else if let Some(v) = first_undefined_local_read(c.body.as_ref(), defined)
                        .filter(|v| {
                            // Bind only a var read NOWHERE outside this
                            // catch: ensure_declared would hoist an
                            // outside-read var to a method local, and
                            // consuming it as the catch parameter would
                            // scope it too narrowly.
                            let in_catch = count_locals_stmts(std::slice::from_ref(c.body.as_ref()));
                            reads_all.get(v).copied().unwrap_or(0)
                                == in_catch.get(v).copied().unwrap_or(0)
                        })
                        .filter(|v| {
                            // And only an EXCEPTION-typed var: the
                            // move-exception registers carry the handler
                            // type — a plain local pending its hoisted
                            // declaration (StringBuilder sb) must not be
                            // consumed as the catch parameter (reqable
                            // amazon: the declaration vanished and its
                            // outer readers broke).
                            let ty = vt.var(*v).ty.erased();
                            let exc = c
                                .exc
                                .first()
                                .cloned()
                                .unwrap_or_else(|| "java/lang/Throwable".into());
                            matches!(&ty, JavaType::Object(o)
                                if o.as_ref() == exc.as_ref()
                                    || o.as_ref() == "java/lang/Throwable")
                        })
                    {
                        // The handler's first statement is not the
                        // move-exception def (the d8 synchronized pattern
                        // leads with MonitorExit): the register the lifter
                        // minted for move-exception is still READ in the
                        // body (`throw th;`) with no defining statement
                        // anywhere. Bind IT as the catch parameter —
                        // otherwise emit printed `catch (Throwable ignored)`
                        // over an undeclared `throw th` (definite-assignment
                        // failure, 6.4k weibo sites).
                        c.var = v;
                        fallback_bound.push(v);
                    } else if let Some(v) =
                        first_thrown_unassigned_local(c.body.as_ref(), vt, assigned)
                            .filter(|v| {
                                let in_catch =
                                    count_locals_stmts(std::slice::from_ref(c.body.as_ref()));
                                reads_all.get(v).copied().unwrap_or(0)
                                    == in_catch.get(v).copied().unwrap_or(0)
                            })
                            .filter(|v| {
                                // Same exception-type gate: the hoisted
                                // `Throwable th;` declares the var but the
                                // move-exception never assigned it.
                                let ty = vt.var(*v).ty.erased();
                                let exc = c
                                    .exc
                                    .first()
                                    .cloned()
                                    .unwrap_or_else(|| "java/lang/Throwable".into());
                                matches!(&ty, JavaType::Object(o)
                                    if o.as_ref() == exc.as_ref()
                                        || o.as_ref() == "java/lang/Throwable")
                            })
                    {
                        // Declared-never-assigned: `Throwable th;` hoisted
                        // by an earlier phase, the catch body's `throw th`
                        // its only use — the move-exception assignment was
                        // never materialized. Bind th as the catch
                        // parameter and drop the bare declaration.
                        c.var = v;
                        fallback_bound.push(v);
                    }
                }
                bind_catches_walk(&mut c.body, vt, defined, reads_all, assigned, fallback_bound);
            }
            if let Some(f) = finally {
                bind_catches_walk(f.as_mut(), vt, defined, reads_all, assigned, fallback_bound);
            }
        }
        Stmt::Block(v) => {
            for x in v.iter_mut() {
                bind_catches_walk(x, vt, defined, reads_all, assigned, fallback_bound);
            }
        }
        Stmt::If {
            then_stmt,
            else_stmt,
            ..
        } => {
            bind_catches_walk(then_stmt, vt, defined, reads_all, assigned, fallback_bound);
            if let Some(e) = else_stmt {
                bind_catches_walk(e, vt, defined, reads_all, assigned, fallback_bound);
            }
        }
        Stmt::While { body, .. } | Stmt::DoWhile { body, .. } => bind_catches_walk(body, vt, defined, reads_all, assigned, fallback_bound),
        Stmt::For { init, body, .. } => {
            for x in init.iter_mut() {
                bind_catches_walk(x, vt, defined, reads_all, assigned, fallback_bound);
            }
            bind_catches_walk(body, vt, defined, reads_all, assigned, fallback_bound);
        }
        Stmt::ForEach { body, .. }
        | Stmt::Labeled { body, .. }
        | Stmt::Synchronized { body, .. } => bind_catches_walk(body, vt, defined, reads_all, assigned, fallback_bound),
        Stmt::Switch { cases, default, .. } => {
            for c in cases.iter_mut() {
                for x in c.body.iter_mut() {
                    bind_catches_walk(x, vt, defined, reads_all, assigned, fallback_bound);
                }
            }
            if let Some(d) = default {
                bind_catches_walk(d, vt, defined, reads_all, assigned, fallback_bound);
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
        Stmt::TryWithResources {
            resources,
            body,
            catches,
            finally,
        } => {
            for r in resources.iter_mut() {
                f(r);
            }
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
        loop {
            match v.last_mut() {
                Some(Stmt::Return(None)) => {
                    v.pop();
                }
                // The structurer can close a region in a bare nested
                // block; a `return;` at its tail is still a dangling
                // statement (inside a static initializer it is illegal
                // outright — clinit's closing return).
                Some(Stmt::Block(_)) => {
                    let last = v.last_mut().unwrap();
                    let before = match last {
                        Stmt::Block(b) => b.len(),
                        _ => 0,
                    };
                    strip_trailing_void_return(last);
                    let after = match last {
                        Stmt::Block(b) => b.len(),
                        _ => 0,
                    };
                    if after == before {
                        break; // nothing stripped inside
                    }
                }
                _ => break,
            }
        }
    }
}

/// `if (c) { } else { B }` → `if (!c) { B }` — the empty-then shape is
/// how the structurer lands an inverted diamond, and source never writes
/// it (jadx prints the positive form). negate() carries De Morgan so
/// composed conditions stay clean.
pub fn invert_empty_thens(s: &mut Stmt) {
    walk_mut_deep(s, &mut |st| {
        if let Stmt::If {
            cond,
            then_stmt,
            else_stmt,
        } = st
        {
            let then_empty = matches!(&**then_stmt, Stmt::Block(v) if v.is_empty());
            if then_empty {
                if let Some(els) = else_stmt.take() {
                    let c = std::mem::replace(cond, Expr::Const(ConstVal::Int(0)));
                    *cond = jdc_core::convert::negate(c);
                    *then_stmt = els;
                }
            }
        }
    });
}

/// Fold if-diamonds back into short-circuit conditions (DAD's
/// short_circuit_struct, statement level). The structurer emits nested
/// ifs for `a && b` / `a || b` bytecode diamonds; javac source almost
/// never nests them, and jadx folds all four shapes:
///   if (c1) { if (c2) {T} else {F} } else {F}  →  if (c1 && c2) {T} else {F}
///   if (c1) { if (c2) {F} else {T} } else {F}  →  if (c1 && !c2) {T} else {F}
///   if (c1) {T} else { if (c2) {T} else {F} }  →  if (c1 || c2) {T} else {F}
///   if (c1) {T} else { if (c2) {F} else {T} }  →  if (c1 || !c2) {T} else {F}
/// Branch identity is deep structural equality (Stmt: PartialEq);
/// iterate to a fixpoint so chained diamonds `(a && b) && c` collapse.
pub fn fold_short_circuits(s: &mut Stmt) {
    for _ in 0..8 {
        let mut changed = false;
        walk_mut_deep(s, &mut |st| {
            if try_fold_diamond(st) {
                changed = true;
            }
        });
        if !changed {
            break;
        }
    }
}

fn try_fold_diamond(st: &mut Stmt) -> bool {
    enum Shape {
        ThenAnd,
        ThenAndNot,
        ElseOr,
        ElseOrNot,
        BareAnd,
        BareAndNot,
    }
    // Probe the shape on an immutable borrow first (the fold takes the
    // whole If apart; matching and rebuilding inside one borrow is not
    // expressible).
    let shape = match &*st {
        // One-sided diamonds: the shared branch is the implicit empty
        // fall-through (`if (c1) { if (c2) {T} }` → `if (c1 && c2) {T}`).
        Stmt::If {
            then_stmt,
            else_stmt: None,
            ..
        } => match &**then_stmt {
            Stmt::If {
                then_stmt: t2,
                else_stmt: None,
                ..
            } if !matches!(&**t2, Stmt::Block(v) if v.is_empty()) => Some(Shape::BareAnd),
            Stmt::If {
                then_stmt: t2,
                else_stmt: Some(_),
                ..
            } if matches!(&**t2, Stmt::Block(v) if v.is_empty()) => Some(Shape::BareAndNot),
            _ => None,
        },
        Stmt::If {
            then_stmt,
            else_stmt: Some(els),
            ..
        } => match (&**then_stmt, &**els) {
            (Stmt::If { else_stmt: Some(f2), .. }, _) if f2.as_ref() == els.as_ref() => {
                Some(Shape::ThenAnd)
            }
            (Stmt::If { then_stmt: t2, else_stmt: Some(_), .. }, _)
                if t2.as_ref() == els.as_ref() =>
            {
                Some(Shape::ThenAndNot)
            }
            (_, Stmt::If { then_stmt: t2, else_stmt: Some(_), .. })
                if t2.as_ref() == then_stmt.as_ref() =>
            {
                Some(Shape::ElseOr)
            }
            (_, Stmt::If { else_stmt: Some(f2), .. })
                if f2.as_ref() == then_stmt.as_ref() =>
            {
                Some(Shape::ElseOrNot)
            }
            _ => None,
        },
        _ => None,
    };
    let Some(shape) = shape else {
        return false;
    };

    let taken = std::mem::replace(st, Stmt::Block(vec![]));
    // Bare (no-else) diamonds fold without an else at all.
    if matches!(shape, Shape::BareAnd | Shape::BareAndNot) {
        let Stmt::If {
            cond: c1,
            then_stmt,
            else_stmt: None,
        } = taken
        else {
            unreachable!()
        };
        let Stmt::If {
            cond: c2,
            then_stmt: t2,
            else_stmt: f2,
        } = *then_stmt
        else {
            unreachable!()
        };
        let sc = |op: BinOp, l: Expr, r: Expr| Expr::Bin {
            op,
            l: Box::new(l),
            r: Box::new(r),
            ty: None,
        };
        match shape {
            // if (c1 && c2) {T}
            Shape::BareAnd => {
                *st = Stmt::If {
                    cond: sc(BinOp::LogAnd, c1, c2),
                    then_stmt: t2,
                    else_stmt: None,
                };
            }
            // if (c1) { if (c2) {} else {T} }  →  if (c1 && !c2) {T}
            _ => {
                let body = f2.unwrap();
                *st = Stmt::If {
                    cond: sc(
                        BinOp::LogAnd,
                        c1,
                        Expr::Un {
                            op: UnOp::Not,
                            e: Box::new(c2),
                        },
                    ),
                    then_stmt: body,
                    else_stmt: None,
                };
            }
        }
        return true;
    }
    let Stmt::If {
        cond: c1,
        then_stmt,
        else_stmt: Some(els),
    } = taken
    else {
        unreachable!("shape probe guaranteed an If with else")
    };
    let sc = |op: BinOp, l: Expr, r: Expr| Expr::Bin {
        op,
        l: Box::new(l),
        r: Box::new(r),
        ty: None,
    };
    let not = |e: Expr| Expr::Un {
        op: UnOp::Not,
        e: Box::new(e),
    };
    match shape {
        Shape::BareAnd | Shape::BareAndNot => unreachable!("handled above"),
        Shape::ThenAnd | Shape::ThenAndNot => {
            let Stmt::If {
                cond: c2,
                then_stmt: t2,
                else_stmt: Some(f2),
            } = *then_stmt
            else {
                unreachable!()
            };
            let (nc, body, alt) = match shape {
                // if (c1 && c2) {T} else {F}
                Shape::ThenAnd => (sc(BinOp::LogAnd, c1, c2), t2, f2),
                // if (c1 && !c2) {T} else {F}   (inner: {F} else {T})
                _ => (sc(BinOp::LogAnd, c1, not(c2)), f2, t2),
            };
            *st = Stmt::If {
                cond: nc,
                then_stmt: body,
                else_stmt: Some(alt),
            };
        }
        Shape::ElseOr | Shape::ElseOrNot => {
            let Stmt::If {
                cond: c2,
                then_stmt: t2,
                else_stmt: Some(f2),
            } = *els
            else {
                unreachable!()
            };
            // The surviving then-body is the OUTER then (identical to the
            // matching inner branch by the probe).
            let body = then_stmt;
            let (nc, alt) = match shape {
                // if (c1 || c2) {T} else {F}   (inner: {T} else {F})
                Shape::ElseOr => (sc(BinOp::LogOr, c1, c2), f2),
                // if (c1 || !c2) {T} else {F}  (inner: {F} else {T})
                _ => (sc(BinOp::LogOr, c1, not(c2)), t2),
            };
            *st = Stmt::If {
                cond: nc,
                then_stmt: body,
                else_stmt: Some(alt),
            };
        }
    }
    true
}

/// A static initializer cannot contain `return` in source form — the
/// clinit's closing return is a method-level artifact, but the
/// structurer can leave it nested inside loops/branches where the
/// top-level strip cannot see it (x2/a: `static { while { ...; return;
/// } }` — "return outside method", 184 sites on reqable).
pub fn strip_clinit_returns(s: &mut Stmt) {
    walk_mut_deep(s, &mut |st| {
        if let Stmt::Block(v) = st {
            v.retain(|x| !matches!(x, Stmt::Return(None)));
        }
    });
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
/// True when `e` evaluates to an object reference — a legal null-compare
/// side: locals via the reference table, everything else via its own type
/// (fields like `pi.versionName != 0` and call results are references too;
/// constants never are).
fn is_obj_expr(e: &Expr, obj_var: &dyn Fn(u32) -> bool) -> bool {
    match e {
        Expr::Local { var, .. } => obj_var(*var),
        Expr::Const(_) => false,
        _ => e.type_ref().erased().is_reference(),
    }
}

/// `obj == 0` / `0 == obj` → `obj == null`: replace the CONST-0 side.
/// The previous shape replaced the LOCAL side instead — every object
/// null-check in the corpus rendered as `null != 0` (4,598 hits in
/// reqable alone) and the real operand vanished from the condition.
fn null_side_rewrite(x: &mut Expr, obj_var: &dyn Fn(u32) -> bool) {
    if let Expr::Bin { op, l, r, .. } = x {
        if !matches!(op, BinOp::Eq | BinOp::Ne) {
            return;
        }
        let l_zero = matches!(&**l, Expr::Const(ConstVal::Int(0)));
        let r_zero = matches!(&**r, Expr::Const(ConstVal::Int(0)));
        if l_zero && !r_zero && is_obj_expr(r, obj_var) {
            **l = Expr::Const(ConstVal::Null);
        } else if r_zero && !l_zero && is_obj_expr(l, obj_var) {
            **r = Expr::Const(ConstVal::Null);
        }
    }
}

pub fn fused_expr_rewrites(s: &mut Stmt, vt: &VarTable) {
    // var ids are dense: a byte table beats a HashSet lookup.
    let mut obj_vars: Vec<bool> = Vec::with_capacity(vt.vars.len());
    for v in &vt.vars {
        obj_vars.push(v.ty.erased().is_reference());
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
                        desc: std::sync::Arc::new(desc),
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
            // 2. null compares (no any_obj gate: the object side may be
            // a field/call whose type is not in the local table).
            null_side_rewrite(x, &|v| obj_vars.get(v as usize).copied().unwrap_or(false));
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
    // 4. null into reference-typed assignment targets. The register
    //    machine stores null as const-0; return/throw/field-store/invoke
    //    argument paths were normalized in the lifter, but a null that
    //    MATERIALIZES into a local was rendered as `str = 0;` — javac
    //    "int cannot be converted to String" (the single biggest error
    //    family on real corpora: d8 emits null locals this way after
    //    every `x = null` branch).
    walk_mut_deep(s, &mut |st| {
        if let Stmt::ExprStmt(Expr::Assign { target, value, .. }) = st {
            let tgt_is_obj = match &**target {
                Expr::Local { var, .. } => {
                    obj_vars.get(*var as usize).copied().unwrap_or(false)
                }
                other => other.type_ref().erased().is_reference(),
            };
            if tgt_is_obj {
                if let Expr::Const(ConstVal::Int(0)) = &**value {
                    **value = Expr::Const(ConstVal::Null);
                }
            }
        } else if let Stmt::LocalDef { var, init, .. } = st {
            if obj_vars.get(*var as usize).copied().unwrap_or(false) {
                if let Some(iv) = init {
                    if let Expr::Const(ConstVal::Int(0)) = iv {
                        *iv = Expr::Const(ConstVal::Null);
                    }
                }
            }
        }
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
                        desc: std::sync::Arc::new(desc),
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
    let mut touched = HashSet::default();
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
    let mut appended_stmts: HashSet<u32> = HashSet::default();
    walk_all(s, &mut |st| {
        if let Stmt::ExprStmt(Expr::Method {
            cls,
            name,
            owner,
            args,
            ..
        }) = st
        {
            if name.as_ref() == "append" && is_string_builder(cls) && args.len() == 1 {
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
        let mut reads: HashSet<u32> = HashSet::default();
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
            Stmt::ExprStmt(e @ (Expr::PreIncDec { .. } | Expr::PostIncDec { .. })) => {
                // `v++` is a read-modify-WRITE of v: counting it as a
                // plain read makes v a single-assign/single-read forward
                // candidate, and value-forwarding then fabricates `5++`
                // (or drops v's def and leaves ++ on an undefined name).
                let inner = match e {
                    Expr::PreIncDec { e, .. } | Expr::PostIncDec { e, .. } => e,
                    _ => unreachable!(),
                };
                if let Expr::Local { var, .. } = &**inner {
                    grow_to(&mut a.assigns, *var);
                    let idx = *var as usize;
                    a.assigns[idx] += 1;
                    if idx < a.values.len() {
                        a.values[idx] = None;
                    }
                    return;
                }
                vec![e]
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
            if name.as_ref() == "toString" && args.is_empty() && is_string_builder(cls) {
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
                        // NEVER fold an empty chain: d8 splits builder
                        // chains across alias registers (`v2 = v0.append
                        // (x); v2.append(y); v0.toString()`) — the traced
                        // chain sees a bare `new StringBuilder` and would
                        // fold toString() to "" (a wrong VALUE, silently:
                        // lab package Obf.label). With zero parts the
                        // call stays — always correct, usually folded
                        // elsewhere once the parts are visible.
                        if !parts.is_empty() {
                            *x = Expr::StringConcat(parts);
                        }
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
        } if name.as_ref() == "append" && is_string_builder(cls) && args.len() == 1 => {
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
                    parts.push(ConcatPart::Const(sv.to_string()));
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
        Expr::Method { name, cls, .. } => name.as_ref() == "append" && is_string_builder(cls),
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
    let mut cand = vec![false; n_vars];
    let mut edges: Vec<Vec<u32>> = vec![Vec::new(); n_vars];
    for (v, cand_v) in cand.iter_mut().enumerate() {
        if assigns.get(v).copied().unwrap_or(0) != 1 || reads.get(v).copied().unwrap_or(0) != 1 {
            continue;
        }
        if let Some(val) = values.get(v).and_then(|o| o.as_ref()) {
            let mut refs = HashSet::default();
            collect_vars(val, &mut refs);
            if refs.iter().any(|r| assigns[*r as usize] > 1) {
                continue;
            }
            // Growth-graph edge set, built in the same walk: inlining v
            // inserts a clone of its value, and every Local inside the
            // clone is replaced in turn.
            edges[v] = refs.into_iter().collect();
        }
        *cand_v = true;
    }

    // Cycle rejection on the growth graph. A def-reference cycle
    // (v = f(w), w = g(v) — loop-carried register rotation reaching the
    // pass as two mutually-referencing single-assign/single-read locals)
    // re-introduces the other cycle Local at every replacement level, so
    // deep_rewrite grows the tree one layer per level and never
    // terminates: weixin's com/tencent/mm/plugin/appbrand/widget/input/b4
    // exhausted a 64MB worker stack at ~300k recursion frames. Edges into
    // non-candidates are harmless (they are never replaced, so growth
    // dies there — and they carry no outgoing edges).
    //
    // Three-color DFS, iterative: a legit 60k-long single-use chain must
    // not trade one stack overflow for another. A GRAY child closes a
    // cycle; `bad[v]` (v on a cycle, or v's inlined closure grows into
    // one) then taints the whole current path — everything on it reaches
    // the cycle. Black verdicts memoize: a node whose subtree was proven
    // clean cannot grow a cycle later.
    let mut color = vec![0u8; n_vars]; // 0 white, 1 gray, 2 black
    let mut bad = vec![false; n_vars];
    for root in 0..n_vars {
        if color[root] != 0 || edges[root].is_empty() {
            continue;
        }
        color[root] = 1;
        let mut stack: Vec<(usize, usize)> = vec![(root, 0)];
        while let Some(top) = stack.last_mut() {
            let v = top.0;
            let i = top.1;
            top.1 += 1;
            if i < edges[v].len() {
                let r = edges[v][i] as usize;
                if color[r] == 1 {
                    for &(pn, _) in &stack {
                        bad[pn] = true;
                    }
                } else if color[r] == 0 {
                    color[r] = 1;
                    stack.push((r, 0));
                } else if bad[r] {
                    for &(pn, _) in &stack {
                        bad[pn] = true;
                    }
                }
            } else {
                color[v] = 2;
                stack.pop();
            }
        }
    }
    let single: Vec<bool> = (0..n_vars).map(|v| cand[v] && !bad[v]).collect();
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
            deep_rewrite_reads(e, &mut |x| {
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
            // `v++` writes v — not a read (a compound `a[i]++` still
            // reads its owner/index subtree).
            Stmt::ExprStmt(e @ (Expr::PreIncDec { .. } | Expr::PostIncDec { .. })) => {
                let inner = match e {
                    Expr::PreIncDec { e, .. } | Expr::PostIncDec { e, .. } => e,
                    _ => unreachable!(),
                };
                if matches!(**inner, Expr::Local { .. }) {
                    Vec::new()
                } else {
                    vec![e]
                }
            }
            Stmt::ExprStmt(e) | Stmt::Throw(e) | Stmt::MonitorEnter(e) | Stmt::MonitorExit(e) => {
                vec![e]
            }
            Stmt::Return(Some(e)) => vec![e],
            Stmt::LocalDef { init: Some(e), .. } => vec![e],
            Stmt::If { cond, .. } => vec![cond],
            Stmt::While { cond, .. } => vec![cond],
            Stmt::DoWhile { cond, .. } => vec![cond],
            // Read sites that are NOT statement children (walk_all recurses
            // into bodies but these payloads are expressions on the node
            // itself). Omitting them under-counts reads, which would let
            // drop_dead_locals over-prune a var whose only use is a switch
            // selector / loop condition / lock / iterable.
            Stmt::Switch { selector, .. } => vec![selector],
            Stmt::ForEach { iterable, .. } => vec![iterable],
            Stmt::Synchronized { lock, .. } => vec![lock],
            Stmt::For { cond, update, .. } => {
                let mut v: Vec<&Expr> = Vec::with_capacity(update.len() + 1);
                if let Some(c) = cond {
                    v.push(c);
                }
                v.extend(update.iter());
                v
            }
            Stmt::Assert { cond, msg } => {
                let mut v: Vec<&Expr> = vec![cond];
                if let Some(m) = msg {
                    v.push(m);
                }
                v
            }
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
                            deep_rewrite_reads(e, &mut |x| {
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
    let n = vt.vars.len();
    // (type, strong) — DIRECTIONAL evidence. Strong facts (an assigned
    // value's type, the declared return/throw/monitor type) DEFINE the
    // variable; weak facts (call argument expectations, receiver
    // contexts, numeric literals) only constrain a use. jadx's bound
    // system carries the same direction; a flat pool let a weak
    // expectation (`v26 = p1` with boolean p1 beside `v26 = 0` sugar)
    // outvote the definition.
    let mut evidence: Vec<Vec<(JavaType, bool)>> = vec![Vec::new(); n];
    let ev = |evidence: &mut Vec<Vec<(JavaType, bool)>>, var: u32, t: JavaType, strong: bool| {
        if (var as usize) < evidence.len() {
            evidence[var as usize].push((t, strong));
        }
    };

    walk_all(body, &mut |st| match st {
        Stmt::LocalDef { var, init, .. } => {
            if let Some(e) = init {
                expr_evidence(e, &mut |v, t| ev(&mut evidence, v, t, false));
                // The initializer DEFINES the declared type: `long v = l(...)`
                // must not stay `int v` (silent 64-bit truncation in the
                // eyes of a reader; javac rejects it as lossy). Null
                // carries no type (it would DOWNGRADE String to Object).
                // Literals are weak (0/1 is boolean sugar half the time);
                // typed producers and parameter sources are strong;
                // local-to-local copies are weak (register reuse).
                let strong = match e {
                    Expr::Const(_) => false,
                    Expr::Local { var: src, .. } => {
                        let src_ty = vt.vars.get(*src as usize).map(|v| v.ty.erased());
                        let tgt_ty = vt.vars.get(*var as usize).map(|v| v.ty.erased());
                        match (src_ty, tgt_ty) {
                            (Some(s), Some(g)) => {
                                (s.is_numeric() && g.is_numeric())
                                    || (s.is_reference() && g.is_reference())
                            }
                            _ => false,
                        }
                    }
                    _ => true,
                };
                ev(&mut evidence, *var, e.type_ref().erased(), strong);
            }
        }
        Stmt::ExprStmt(e) => {
            // Assignment targets: a typed PRODUCER (method/new/field) or a
            // PARAMETER source is a STRONG definition (`v26 = p1` with
            // boolean p1). A local-to-local copy is weak — register reuse
            // and merge materialization emit exactly that shape with
            // mismatched types (`sb7 = compareTo10` in a Kotlin when).
            // Literals stay weak.
            if let Expr::Assign { target, value, .. } = e {
                // A field WRITE through a local (`v.f = x`, dex iput)
                // proves v is a reference of the field's declaring
                // class AT THAT POINT — an iput on a boolean register
                // cannot exist in valid dex. Strong: it must outrank a
                // strong boolean copy chain into the same reused slot
                // (weixin coroutine state machines).
                if let Expr::Field { owner: Some(o), cls, is_static: false, .. } = &**target {
                    if cls.is_empty() {
                        // array-length pseudo-field: no declaring class
                    } else if let Expr::Local { var, .. } = &**o {
                        ev(
                            &mut evidence,
                            *var,
                            JavaType::Object(cls.clone()),
                            true,
                        );
                    }
                }
                if let Expr::Local { var, .. } = &**target {
                    let strong = match &**value {
                        Expr::Const(_) => false,
                        Expr::Local { var: src, .. } => {
                            // A local copy is strong when the source and
                            // the target's register type are the same
                            // FAMILY (numeric↔numeric, reference↔
                            // reference) — a cross-family copy (int into
                            // a StringBuilder local) is merge-material
                            // residue and stays weak.
                            let src_ty = vt.vars.get(*src as usize).map(|v| v.ty.erased());
                            let tgt_ty = vt.vars.get(*var as usize).map(|v| v.ty.erased());
                            match (src_ty, tgt_ty) {
                                (Some(s), Some(g)) => {
                                    (s.is_numeric() && g.is_numeric())
                                        || (s.is_reference() && g.is_reference())
                                }
                                _ => false,
                            }
                        }
                        _ => true,
                    };
                    ev(&mut evidence, *var, value.type_ref().erased(), strong);
                }
            }
            expr_evidence(e, &mut |v, t| ev(&mut evidence, v, t, false));
        }
        Stmt::Throw(e) => {
            expr_evidence(e, &mut |v, t| ev(&mut evidence, v, t, false));
            if let Expr::Local { var, .. } = e {
                ev(
                    &mut evidence,
                    *var,
                    JavaType::Object("java/lang/Throwable".into()),
                    true,
                );
            }
        }
        Stmt::Return(Some(e)) => {
            expr_evidence(e, &mut |v, t| ev(&mut evidence, v, t, false));
            if let Expr::Local { var, .. } = e {
                ev(&mut evidence, *var, ret.clone(), true);
            }
        }
        Stmt::MonitorEnter(e) | Stmt::MonitorExit(e) => {
            if let Expr::Local { var, .. } = e {
                ev(
                    &mut evidence,
                    *var,
                    JavaType::Object("java/lang/Object".into()),
                    true,
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
                    ev(&mut evidence, *v0, JavaType::Array(Box::new(JavaType::Int)), true);
                } else {
                    ev(
                        &mut evidence,
                        *v0,
                        JavaType::Object("java/lang/Object".into()),
                        true,
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

        // Vars dereferenced as field/method receivers or arrays: their
    // resolved type must be a dereferenceable class — a boxed Boolean
    // in the strong set (Kotlin Result registers hold `Boolean | impl`
    // across coroutine case arms) must lose to the real class even
    // when the Boolean evidence comes first (weixin ry0/h2's
    // `Boolean bool19` receiving `bool19.d = x`).
    let mut derefed: Vec<bool> = vec![false; vt.vars.len()];
    mark_derefs(body, &mut derefed);
    // Array-indexed vars: their resolved type must be an ARRAY when
    // the evidence has one (`num4[v68]` with Integer-typed num4 —
    // 需要数组但找到Integer family); member derefs keep the class
    // preference below.
    let mut arr_derefed: Vec<bool> = vec![false; vt.vars.len()];
    visit_all_exprs(body, &mut |x| {
        if let Expr::ArrayIndex { array, .. } = x {
            if let Expr::Local { var, .. } = &**array {
                if (*var as usize) < arr_derefed.len() {
                    arr_derefed[*var as usize] = true;
                }
            }
        }
        // `v != null` is STRONG reference evidence: the lifter only
        // renders the null form when the dex value view held a
        // reference register at that pc — an int-typed generation
        // compared against null is phi-confluence residue (yq0/g1's
        // `v95_g12 != null`, 546-line 二元运算符 family). Strong Object
        // makes the resolver retype and split_generations separate the
        // int writes into their own generation.
        if let Expr::Bin { op, l, r, .. } = x {
            if matches!(op, BinOp::Eq | BinOp::Ne)
                && (matches!(&**r, Expr::Const(ConstVal::Null))
                    || matches!(&**l, Expr::Const(ConstVal::Null)))
            {
                for side in [l, r] {
                    if let Expr::Local { var, .. } = &**side {
                        ev(
                            &mut evidence,
                            *var,
                            JavaType::Object("java/lang/Object".into()),
                            true,
                        );
                    }
                }
            }
        }
    });
    const FINAL_JDK: &[&str] = &[
        "java/lang/Boolean",
        "java/lang/String",
        "java/lang/Integer",
        "java/lang/Long",
        "java/lang/Short",
        "java/lang/Byte",
        "java/lang/Character",
        "java/lang/Float",
        "java/lang/Double",
    ];
    for (i, evs) in evidence.iter().enumerate() {
        let info = &vt.vars[i];
        if info.is_param {
            continue;
        }
        let strong: Vec<JavaType> = evs
            .iter()
            .filter(|(_, s)| *s)
            .map(|(t, _)| t.clone())
            .collect();
        let all: Vec<JavaType> = evs.iter().map(|(t, _)| t.clone()).collect();
        if info.ty.erased().is_reference() {
            // Materialization residue: no strong definition, and the weak
            // pool names ≥2 DIFFERENT classes (a Kotlin `when` lowered
            // every branch's value into one register slot) — neither
            // class can win, every assignment needs boxing headroom:
            // widen to Object (uses get receiver casts).
            if strong.is_empty() {
                let refs: std::collections::HashSet<&str> = all
                    .iter()
                    .filter_map(|t| match t {
                        JavaType::Object(n) if n.as_ref() != "java/lang/Object" => {
                            Some(n.as_ref())
                        }
                        _ => None,
                    })
                    .collect();
                let mixed = all.iter().any(|t| t.is_numeric());
                if refs.len() >= 2 || (mixed && !refs.is_empty()) || (mixed && all.iter().any(|t| matches!(t, JavaType::Array(_)))) {
                    vt.vars[i].ty =
                        TypeRef::J(JavaType::Object("java/lang/Object".into()));
                    continue;
                }
            }
                        // Array-dereferenced vars prefer array evidence (an
            // Integer producer cannot be indexed).
            if arr_derefed[i] {
                let arr = strong
                    .iter()
                    .chain(all.iter())
                    .find(|t| matches!(t, JavaType::Array(_)))
                    .cloned();
                if let Some(t) = arr {
                    vt.vars[i].ty = TypeRef::J(t);
                    continue;
                }
            }
            // Strong definitions outrank weak expectations. A
            // dereferenced var prefers a real class over final JDK
            // boxes (Boolean can never carry `.d = x`).
            let deref_pick = || {
                if !derefed[i] {
                    return None;
                }
                strong
                    .iter()
                    .find(|t| {
                        matches!(t, JavaType::Object(n)
                            if !n.is_empty()
                                && n.as_ref() != "java/lang/Object"
                                && !FINAL_JDK.contains(&n.as_ref()))
                    })
                    .cloned()
            };
            if let Some(t) = deref_pick()
                .or_else(|| pick_object(&strong))
                .or_else(|| pick_object(&all))
            {
                vt.vars[i].ty = TypeRef::J(t);
            }
        } else if let Some(t) = pick_object(&strong) {
            // A strong reference definition (typed producer or field
            // write) outranks a strong boolean copy: Boolean assigns
            // INTO an Object slot legally, never the reverse.
            vt.vars[i].ty = TypeRef::J(t);
        } else if strong.contains(&JavaType::Boolean) {
            // A boolean-typed SOURCE assigned into the variable is a
            // definition (`v26 = p1` with boolean p1); the 0/1 literals
            // that share the pool are boolean sugar as often as not.
            vt.vars[i].ty = TypeRef::J(JavaType::Boolean);
        } else if !all.is_empty() && all.iter().all(|t| t.is_numeric()) {
            if let Some(t) = pick_numeric(&all) {
                vt.vars[i].ty = TypeRef::J(t);
            }
        } else {
            // Mixed-family materialization on a numeric-declared slot
            // (int slot receiving StringBuilders — the register was the
            // `when` accumulator): Object, same as the reference side.
            let refs = all.iter().filter(|t| t.is_reference()).count();
            let nums = all.iter().filter(|t| t.is_numeric()).count();
            if refs > 0 && nums > 0 {
                vt.vars[i].ty =
                    TypeRef::J(JavaType::Object("java/lang/Object".into()));
            } else if let Some(t) = pick_object(&strong).or_else(|| pick_object(&all)) {
                vt.vars[i].ty = TypeRef::J(t);
            }
        }
    }

    // Rewrite embedded Local types. Borrowed view + write-only-on-change:
    // the table clone was n_vars JavaType clones per method, and the
    // rewrite cloned a type into EVERY Local node — most already carry
    // the right one (JavaType::Object clones allocate).
    let types: Vec<&TypeRef> = vt.vars.iter().map(|v| &v.ty).collect();
    rewrite_exprs(body, &mut |e| {
        deep_rewrite(e, &mut |x| {
            if let Expr::Local { var, ty } = x {
                if let Some(want) = types.get(*var as usize) {
                    if ty != *want {
                        *ty = (*want).clone();
                    }
                }
            }
        });
    });

    // Numeric literals take their variable's declared width (`double v = 0L`
    // prints as `0.0`; `int x = 5L` as `5`).
    coerce_num_consts(body, &types);
}

fn coerce_num_consts(body: &mut Stmt, types: &[&TypeRef]) {
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
        .find(|t| {
            t.is_reference()
                && !matches!(t, JavaType::Object(n) if n.is_empty() || n.as_ref() == "java/lang/Object")
        })
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
            cls,
            ty,
            is_static,
            ..
        } => {
            if !*is_static && !cls.is_empty() {
                if let Some(o) = owner {
                    if let Expr::Local { var, .. } = &**o {
                        // The field ref's declaring class is dex-exact
                        // evidence — the old hardcoded Object let a
                        // boolean copy chain outvote it (weixin ry0/h2's
                        // `Boolean bool19` receiving `bool19.d = x` —
                        // the 339-line 找不到符号 变量 d family).
                        // EMPTY cls = the array-length pseudo-field
                        // (lift models `a.length` as Field{cls:""}) —
                        // Object("") evidence poisoned pick_object into
                        // empty-typed declarations and `() x` casts.
                        f(*var, JavaType::Object(cls.clone()));
                    }
                }
            }
            let _ = ty;
        }
        // `v != null` / `v == null`: the register holds a reference at
        // that point — weak Object evidence keeps int-typed generations
        // from winning the pool (yq0/g1's `v95_g12 != null` with int
        // v95_g12 — 二元运算符 '!=' 546-line family).
        Expr::Bin { op, l, r, .. }
            if matches!(op, BinOp::Eq | BinOp::Ne)
                && (matches!(&**r, Expr::Const(ConstVal::Null))
                    || matches!(&**l, Expr::Const(ConstVal::Null))) =>
        {
            for side in [l, r] {
                if let Expr::Local { var, .. } = &**side {
                    f(*var, JavaType::Object("java/lang/Object".into()));
                }
            }
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
        Expr::Assign { .. } => {
            // Covered by the typed strong-evidence walk in infer_types;
            // keeping a weak duplicate here let expectations outvote it.
        }
        Expr::Cast { e: inner, .. } => {
            // A cast is an EXPLICIT narrowing at the use site — it must
            // NOT feed the cast target as evidence for the variable
            // (`Object get2 = list.get(2); j((String) get2);` had get2
            // retyped to String, making the assignment incompatible).
            // jadx's bounds carry direction: a USE bound narrows nothing.
            let _ = inner;
        }
        Expr::InstanceOf { e: inner, .. } => {
            let _ = inner;
        }
        _ => {}
    });
}

/// Type inference can leave a specific-reference-typed target assigned
/// from a `java/lang/Object`-typed value: a phi that merged String and
/// Object then settled on String (`String str4; ... str4 = obj;` where
/// `obj` is an Object field — y5/n.java), or an Object local flowing to a
/// typed field. Java requires a narrowing cast there; insert `(T) value`
/// at the USE site (round-40 philosophy: narrow at use, never retype the
/// declaration). Guarded tightly: only when the value's resolved static
/// type is EXACTLY `java/lang/Object` (the untyped top — a known subtype
/// is never re-cast), the value is not a null const (assignable to any
/// ref) nor already a cast, and the target is a specific reference type
/// (Object→int/boolean is unboxing, a different problem left alone).
pub fn insert_object_narrowing_casts(vt: &VarTable, body: &mut Stmt) {
    // Resolve a value's static type through the VarTable for locals (the
    // embedded Local ty can lag infer_types), else the expr's own type.
    let value_ty = |e: &Expr| -> JavaType {
        match e {
            Expr::Local { var, .. } => vt.var(*var).ty.erased(),
            other => other.type_ref().erased(),
        }
    };
    let is_top_object = |e: &Expr| -> bool {
        value_ty(e) == JavaType::Object("java/lang/Object".into())
    };
    // A specific reference target type (a class other than
    // java/lang/Object, or an array — `String[] v = obj` needs the
    // cast exactly like `String v = obj`).
    let specific_ref = |ty: &TypeRef| -> Option<TypeRef> {
        match ty.erased() {
            JavaType::Object(c) if c.as_ref() != "java/lang/Object" => Some(ty.clone()),
            JavaType::Array(_) => Some(ty.clone()),
            _ => None,
        }
    };
    let castable = |e: &Expr| -> bool {
        is_top_object(e)
            && !matches!(e, Expr::Const(_) | Expr::Cast { .. } | Expr::InstanceOf { .. })
    };
    walk_mut_deep(body, &mut |st| match st {
        Stmt::ExprStmt(Expr::Assign {
            target,
            value,
            op: AssignOp::Plain,
            ..
        }) => {
            let tgt = match &**target {
                Expr::Local { var, .. } => vt.var(*var).ty.clone(),
                Expr::Field { ty, .. } => ty.clone(),
                _ => return,
            };
            if let Some(t) = specific_ref(&tgt) {
                if castable(value) {
                    let v = std::mem::replace(value, Box::new(Expr::This));
                    **value = Expr::Cast { ty: t, e: v };
                }
            }
        }
        Stmt::LocalDef { var, init: Some(value), .. } => {
            if let Some(t) = specific_ref(&vt.var(*var).ty) {
                if castable(value) {
                    let v = std::mem::replace(value, Expr::This);
                    *value = Expr::Cast {
                        ty: t,
                        e: Box::new(v),
                    };
                }
            }
        }
        _ => {}
    });
    // Descriptor-exact formal casts at CALL args: the dex already
    // resolved the target method, so casting a top-Object actual to
    // its declared formal cannot shift overload resolution (the r57
    // args lesson applies to GUESSED casts, not descriptor-exact
    // ones). `"source_type:".concat(obj2)`, `new my0.j(obj2, ..)` —
    // Object无法转换为String family.
    walk_stmt_exprs(body, &mut |e| {
        deep_rewrite(e, &mut |x| {
            let (args, arg_tys): (&mut Vec<Expr>, &[JavaType]) = match x {
                Expr::Method { desc, args, is_dynamic: false, .. } => {
                    (args, desc.args.as_slice())
                }
                // Ctor calls are their own variant — the dex resolved the
                // exact <init>, so formal casts are just as safe here
                // (`new r(obj)` — Object无法转换为r family).
                Expr::New { arg_tys, args, .. } => (args, arg_tys.as_slice()),
                _ => return,
            };
            for (i, a) in args.iter_mut().enumerate() {
                let Some(formal) = arg_tys.get(i) else {
                    continue;
                };
                let Some(t) = specific_ref(&TypeRef::J(formal.clone())) else {
                    continue;
                };
                if !castable(a) {
                    continue;
                }
                let v = std::mem::replace(a, Expr::Const(ConstVal::Null));
                *a = Expr::Cast { ty: t, e: Box::new(v) };
            }
        });
    });
}

/// Numeric narrowing/widening mismatches at Assign / LocalDef / Return
/// positions get an explicit cast: dex int-to-byte / long-to-int flows
/// are implicit in the register machine, Java rejects them ("从long
/// 转换到int可能会有损失" — okio Buffer ×321 weibo lines). Casts at
/// these three positions are descriptor-faithful and cannot shift
/// overload resolution (the r57 args-position lesson). Boolean/numeric
/// mixes are NOT castable in Java and stay with the generation-split
/// machinery.
pub fn fix_primitive_assign_casts(vt: &VarTable, body: &mut Stmt, ret_ty: &JavaType) {
    fn numlike(t: &JavaType) -> bool {
        matches!(
            t,
            JavaType::Byte
                | JavaType::Short
                | JavaType::Int
                | JavaType::Char
                | JavaType::Long
                | JavaType::Float
                | JavaType::Double
        )
    }
    fn val_ty(e: &Expr, vt: &VarTable) -> JavaType {
        match e {
            Expr::Local { var, .. } if (*var as usize) < vt.vars.len() => {
                vt.var(*var).ty.erased()
            }
            other => other.type_ref().erased(),
        }
    }
    fn wrap(ty: &JavaType, value: &mut Expr) {
        if matches!(value, Expr::Cast { .. }) {
            return;
        }
        if val_ty_static(value) == *ty {
            return;
        }
        let taken = std::mem::replace(value, Expr::Const(ConstVal::Null));
        *value = Expr::Cast {
            ty: TypeRef::J(ty.clone()),
            e: Box::new(taken),
        };
    }
    fn val_ty_static(e: &Expr) -> JavaType {
        e.type_ref().erased()
    }
    walk_mut_deep(body, &mut |st| match st {
        Stmt::ExprStmt(Expr::Assign {
            target,
            op: AssignOp::Plain,
            value,
        }) => {
            let tt = match &**target {
                Expr::Local { var, .. } if (*var as usize) < vt.vars.len() => {
                    vt.var(*var).ty.erased()
                }
                Expr::Field { ty, .. } => ty.erased(),
                _ => return,
            };
            if !numlike(&tt) || !numlike(&val_ty(value, vt)) {
                return;
            }
            wrap(&tt, value);
        }
        Stmt::LocalDef {
            var,
            init: Some(value),
            ..
        } => {
            if (*var as usize) >= vt.vars.len() {
                return;
            }
            let tt = vt.var(*var).ty.erased();
            if !numlike(&tt) || !numlike(&val_ty(value, vt)) {
                return;
            }
            wrap(&tt, value);
        }
        Stmt::Return(Some(e)) => {
            if !numlike(ret_ty) || !numlike(&val_ty(e, vt)) {
                return;
            }
            wrap(ret_ty, e);
        }
        _ => {}
    });
}

/// `==`/`!=` between UNRELATED class types is a compile error in Java
/// ("不可比较的类型: f0和a") while dex if-eqObj happily compares any two
/// references (weixin fn1/w1 ×298 files). One side takes an `(Object)`
/// witness cast — legal against anything. Interfaces and subtype-related
/// pairs are already comparable and stay untouched; java/lang/Object and
/// arrays-of it likewise.
pub fn fix_incomparable_equality(body: &mut Stmt, vt: &VarTable, pool: &crate::DexPool) {
    fn side_ty(e: &Expr, vt: &VarTable) -> JavaType {
        match e {
            Expr::Local { var, .. } if (*var as usize) < vt.vars.len() => {
                vt.var(*var).ty.erased()
            }
            other => other.type_ref().erased(),
        }
    }
    let incomparable = |a: &JavaType, b: &JavaType| -> bool {
        use JavaType::{Array, Object};
        match (a, b) {
            (Object(x), Object(y)) => {
                if x == y || x.as_ref() == "java/lang/Object" || y.as_ref() == "java/lang/Object"
                {
                    return false;
                }
                let xi = pool.get(x).map(|c| c.is_interface()).unwrap_or(true);
                let yi = pool.get(y).map(|c| c.is_interface()).unwrap_or(true);
                // Unknown classes (framework, not in pool): a cast is
                // harmless but usually unnecessary — treat as comparable
                // to stay conservative.
                if xi || yi {
                    return false;
                }
                !pool.is_subtype(x, y) && !pool.is_subtype(y, x)
            }
            (Array(_), Object(y)) | (Object(y), Array(_)) => {
                y.as_ref() != "java/lang/Object"
                    && y.as_ref() != "java/lang/Cloneable"
                    && y.as_ref() != "java/io/Serializable"
                    && !pool.get(y).map(|c| c.is_interface()).unwrap_or(false)
            }
            _ => false,
        }
    };
    let is_ref = |t: &JavaType| matches!(t, JavaType::Object(_) | JavaType::Array(_));
    walk_stmt_exprs(body, &mut |e| {
        deep_rewrite(e, &mut |x| {
            if let Expr::Bin {
                op: BinOp::Eq | BinOp::Ne,
                l,
                r,
                ..
            } = x
            {
                let lt = side_ty(l, vt);
                let rt = side_ty(r, vt);
                // `obj != 0` → `obj != null` with FINAL types: the
                // lift-time null_side_rewrite ran before infer_types
                // (its obj table saw the pre-inference int), leaving
                // `sQLiteClosable != 0` — "二元运算符 '!=' 的操作数
                // 类型错误" ×700 weixin.
                if is_ref(&lt) && matches!(&**r, Expr::Const(ConstVal::Int(0))) {
                    **r = Expr::Const(ConstVal::Null);
                    return;
                }
                if is_ref(&rt) && matches!(&**l, Expr::Const(ConstVal::Int(0))) {
                    **l = Expr::Const(ConstVal::Null);
                    return;
                }
                if incomparable(&lt, &rt) {
                    let taken = std::mem::replace(l, Box::new(Expr::Const(ConstVal::Null)));
                    **l = Expr::Cast {
                        ty: TypeRef::J(JavaType::Object("java/lang/Object".into())),
                        e: taken,
                    };
                }
            }
        });
    });
}

/// Primitive bridges at CALL/CTOR argument positions. Dex slots are
/// untyped category-1 integers: the verifier happily passes a Z-slot to
/// a `(B)` formal (weibo's Meituan-Robust hotpatch boilerplate boxes
/// boolean params via `new Byte(zreg)` — 4.2k+ `对于Byte(boolean),
/// 找不到合适的构造器`), and obfuscated/Kotlin code passes 0/1 slots to
/// `(Z)` formals (`int无法转换为boolean` at call sites). Java source
/// cannot express either — bridge at the IR level:
///   Boolean actual → numeric formal:  `(byte) (b ? 1 : 0)`
///   numeric actual → Boolean formal:  `x != 0`
/// The target method is DESCRIPTOR-bound (bytecode method_ref), so a
/// cast/compare to the exact formal type cannot flip overload
/// resolution the way r57's inferred object casts did — the rendered
/// call selects the same signature the dex named.
pub fn fix_primitive_arg_bridges(body: &mut Stmt, vt: &VarTable, pool: &crate::DexPool) {
    fn val_ty(e: &Expr, vt: &VarTable) -> JavaType {
        match e {
            Expr::Local { var, .. } => vt.var(*var).ty.erased(),
            other => other.type_ref().erased(),
        }
    }
    #[allow(clippy::type_complexity)]
    let is_bool = |t: &JavaType| matches!(t, JavaType::Boolean);
    let is_num = |t: &JavaType| {
        matches!(
            t,
            JavaType::Byte | JavaType::Short | JavaType::Int | JavaType::Char
                | JavaType::Long | JavaType::Float | JavaType::Double
        )
    };
    // BORROWED-arg form: returns the bridged replacement without
    // consuming the original (a `mem::replace` + `Option` dance dropped
    // the argument on the None path — every Boolean→Boolean arg became
    // a literal `null`: 61k 引用不明确 in one battery run).
    fn bridge(actual: &JavaType, formal: &JavaType, arg: &Expr) -> Option<Expr> {
        if matches!(actual, JavaType::Boolean)
            && matches!(
                formal,
                JavaType::Byte | JavaType::Short | JavaType::Int | JavaType::Char
                    | JavaType::Long | JavaType::Float | JavaType::Double
            )
        {
            Some(Expr::Cast {
                ty: TypeRef::J(formal.clone()),
                e: Box::new(Expr::Cond {
                    c: Box::new(arg.clone()),
                    t: Box::new(Expr::Const(ConstVal::Int(1))),
                    f: Box::new(Expr::Const(ConstVal::Int(0))),
                }),
            })
        } else if matches!(formal, JavaType::Boolean)
            && matches!(
                actual,
                JavaType::Byte | JavaType::Short | JavaType::Int | JavaType::Char
                    | JavaType::Long | JavaType::Float | JavaType::Double
            )
        {
            Some(Expr::Bin {
                op: BinOp::Ne,
                l: Box::new(arg.clone()),
                r: Box::new(Expr::Const(ConstVal::Int(0))),
                ty: Some(TypeRef::J(JavaType::Boolean)),
            })
        } else {
            None
        }
    }
    // Ctors: formal types via the pool (unanimous across same-arity
    // overloads, else skip — ambiguity must not guess).
    let ctor_formals = |cls: &str, n: usize| -> Option<Vec<JavaType>> {
        let c = pool.get(cls)?;
        let mut out: Option<Vec<JavaType>> = None;
        for m in c.all_methods() {
            if &*m.name != "<init>" {
                continue;
            }
            let Some(d) = m.parsed_desc() else { continue };
            if d.args.len() != n {
                continue;
            }
            match &out {
                None => out = Some(d.args.clone()),
                Some(prev) if *prev != d.args => return None,
                Some(_) => {}
            }
        }
        out
    };
    walk_stmt_exprs(body, &mut |e| {
        deep_rewrite(e, &mut |x| match x {
            Expr::Method {
                cls, desc, args, is_static, ..
            } => {
                if args.len() != desc.args.len() {
                    return;
                }
                let _ = (cls, is_static);
                for (a, f) in args.iter_mut().zip(desc.args.iter()) {
                    if !is_bool(&val_ty(a, vt)) && !is_num(&val_ty(a, vt)) {
                        continue;
                    }
                    if !is_bool(f) && !is_num(f) {
                        continue;
                    }
                    if matches!(a, Expr::Cast { .. }) {
                        continue;
                    }
                    if let Some(b) = bridge(&val_ty(a, vt), f, a) {
                        *a = b;
                    }
                }
            }
            Expr::New { cls, args, arg_tys, .. } => {
                let formals_owned = if arg_tys.len() == args.len() && !arg_tys.is_empty() {
                    Some(arg_tys.clone())
                } else {
                    ctor_formals(cls, args.len())
                };
                if let Some(formals) = formals_owned {
                    for (a, f) in args.iter_mut().zip(formals.iter()) {
                        if matches!(a, Expr::Cast { .. }) {
                            continue;
                        }
                        if !is_bool(f) && !is_num(f) {
                            continue;
                        }
                        if let Some(b) = bridge(&val_ty(a, vt), f, a) {
                            *a = b;
                        }
                    }
                }
            }
            _ => {}
        });
    });
}

/// `b ^ 1` / `1 ^ b` with a BOOLEAN operand is the bytecode's boolean
/// negation (`!b`) — weibo kotlin-stdlib `return v2 ^ 1;` ("二元运算符
/// '^' 的操作数类型错误"), and `x ^ true` shapes. Java only types `^`
/// for same-category operands.
/// Rename locals whose name equals a ROOT PACKAGE first segment: a
/// package-qualified render (`v2.n.a` — the FQN fallback a twin-shadowed
/// same-package ref must take) binds its first identifier lexically, and
/// a local `v2` in scope captures it (weixin v2/i: 找不到符号 变量 n on a
/// legit `v2.n.a(this, 0)`). Method-scope renames carry no registry
/// surface — every use renders through this same vt — unlike class/field
/// renames, whose reference coverage blew up five times before.
pub fn deshadow_locals(vt: &mut VarTable, pool: &crate::DexPool) {
    let segs = pool.root_pkg_segs();
    // Import-layer simples: the file renders `import p.h;` + bare `h.e`
    // for obscured refs — a local `h` captures that simple name (locals
    // beat imports in expression position; 无法取消引用int family).
    let obscured = crate::classdec::obscured_simples_snapshot();
    let hit = |name: &str| segs.contains(name) || obscured.contains(name);
    if (segs.is_empty() && obscured.is_empty()) || !vt.vars.iter().any(|v| hit(&v.name)) {
        return;
    }
    let mut taken: jdc_core::FxHashSet<String> =
        vt.vars.iter().map(|v| v.name.clone()).collect();
    for v in vt.vars.iter_mut() {
        if !hit(&v.name) {
            continue;
        }
        let mut k = 0u32;
        let cand = loop {
            k += 1;
            let c = if k == 1 {
                format!("{}x", v.name)
            } else {
                format!("{}x{}", v.name, k)
            };
            if !taken.contains(&c) {
                break c;
            }
        };
        taken.insert(cand.clone());
        v.name = cand;
    }
}

/// Receiver rescue: a Field/Method receiver whose final vt type is
/// PRIMITIVE can never hold the member (structurer tail-copy regions
/// can map the receiver register onto a boolean/int generation —
/// wcdb HandleOperation's `v10_g2.finalizeStatement()` where the
/// statement var is right there; weixin deref-int/bool families,
/// ~2.5k lines). The member descriptor's owner class is authoritative:
/// when EXACTLY ONE var in the method has that type (or a subtype),
/// swap the receiver to it. The pre-rescue output is a guaranteed
/// compile error AND runtime NPE, so the unambiguous swap cannot make
/// it worse; ambiguous sites stay untouched.
pub fn rescue_primitive_receivers(body: &mut Stmt, vt: &VarTable, pool: &crate::DexPool) {
    fn prim(t: &JavaType) -> bool {
        match t {
            JavaType::Int
            | JavaType::Long
            | JavaType::Short
            | JavaType::Byte
            | JavaType::Char
            | JavaType::Float
            | JavaType::Double
            | JavaType::Boolean => true,
            // Boxed JDK finals carry no app members either (`bool19.d`
            // where bool19 came out java/lang/Boolean — the coroutine
            // Result-register conflation).
            JavaType::Object(n) => matches!(
                n.as_ref(),
                "java/lang/Boolean"
                    | "java/lang/String"
                    | "java/lang/Integer"
                    | "java/lang/Long"
                    | "java/lang/Short"
                    | "java/lang/Byte"
                    | "java/lang/Character"
                    | "java/lang/Float"
                    | "java/lang/Double"
            ),
            _ => false,
        }
    }
    walk_stmt_exprs(body, &mut |e| {
        deep_rewrite(e, &mut |x| {
            // Phase 1 (read-only): primitive-typed Local receiver?
            let recv_var = {
                let o: &Expr = match &*x {
                    Expr::Method { owner: Some(o), .. } => o,
                    Expr::Field { owner: Some(o), is_static: false, .. } => o,
                    _ => return,
                };
                let Expr::Local { var, ty } = o else {
                    return;
                };
                let vt_ty = if (*var as usize) < vt.vars.len() {
                    vt.var(*var).ty.erased()
                } else {
                    ty.erased()
                };
                if !prim(&vt_ty) {
                    return;
                }
                *var
            };
            let cls: std::sync::Arc<str> = match &*x {
                Expr::Method { cls, .. } | Expr::Field { cls, .. } => cls.clone(),
                _ => return,
            };
            // Phase 2: vars of the owner type (exact or subtype).
            let mut cands: Vec<u32> = Vec::new();
            for v in &vt.vars {
                if let JavaType::Object(n) = v.ty.erased() {
                    if n.as_ref() == cls.as_ref()
                        || pool.is_subtype(n.as_ref(), cls.as_ref())
                    {
                        cands.push(v.id);
                    }
                }
            }
            let id = if cands.len() == 1 {
                cands[0]
            } else {
                // Lineage disambiguation by SLOT: register reuse makes
                // the Boolean/primitive twin and the object version of
                // one dex register share VarInfo.slot (ry0/h2's
                // `bool19.d` — the v1-typed twin rides the same
                // register). Multiple slot matches stay untouched
                // (deterministic conservatism).
                if cands.is_empty() {
                    return;
                }
                let slot = if (recv_var as usize) < vt.vars.len() {
                    vt.var(recv_var).slot
                } else {
                    return;
                };
                let mut hits: Vec<u32> = cands
                    .into_iter()
                    .filter(|&c| {
                        c != recv_var
                            && (c as usize) < vt.vars.len()
                            && vt.var(c).slot == slot
                    })
                    .collect();
                hits.sort_unstable();
                hits.dedup();
                if hits.len() != 1 {
                    return;
                }
                hits[0]
            };
            // Phase 3: swap.
            let o: &mut Box<Expr> = match x {
                Expr::Method { owner: Some(o), .. } => o,
                Expr::Field { owner: Some(o), is_static: false, .. } => o,
                _ => return,
            };
            if let Expr::Local { var, ty } = &mut **o {
                if *var == recv_var {
                    *var = id;
                    *ty = vt.vars[id as usize].ty.clone();
                }
            }
        });
    });

}

/// Scope-safe arg/return swaps for mistyped generations — runs AFTER
/// ensure_declared hoists every declaration to the method top, so the
/// top_ids visibility precondition holds by construction (the r134
/// falsification: swapping in a block-scoped var broke lexically).
/// Same-slot + type-match + uniqueness gates as the receiver rescue.
pub fn rescue_arg_return_swaps(
    body: &mut Stmt,
    vt: &VarTable,
    pool: &crate::DexPool,
    ret_ty: &JavaType,
) {
    // SCOPE-SAFE arg/return swap: a primitive-typed actual against a
    // specific-reference formal (or a reference-returning `return`) is
    // a mistyped generation — the r134 falsification showed the swap
    // target MUST be lexically visible at the use site, so candidates
    // are restricted to params + TOP-LEVEL declared locals (a hoisted
    // decl is visible to javac name resolution everywhere in the
    // method) AND same-slot (same dex register lineage) AND unique.
    let mut top_ids: jdc_core::FxHashSet<u32> = jdc_core::FxHashSet::default();
    for v in &vt.vars {
        if v.is_param {
            top_ids.insert(v.id);
        }
    }
    if let Stmt::Block(stmts) = body {
        for st in stmts.iter() {
            if let Stmt::LocalDef { var, .. } = st {
                top_ids.insert(*var);
            }
        }
    }
    let ret_wants_ref = match ret_ty {
        JavaType::Object(n) => n.as_ref() != "java/lang/Object",
        JavaType::Array(_) => true,
        _ => false,
    };
    let try_swap = |a: &mut Expr, want: &JavaType| {
        let Expr::Local { var, ty } = &mut *a else {
            return;
        };
        if (*var as usize) >= vt.vars.len() {
            return;
        }
        let avt = vt.var(*var).ty.erased();
        let avt_ref = matches!(avt, JavaType::Object(_) | JavaType::Array(_));
        let want_arr = matches!(want, JavaType::Array(_));
        // Only swap a primitive-typed actual (an Object actual gets the
        // descriptor-exact cast instead — never both).
        if avt_ref && !(avt == JavaType::Object("java/lang/Object".into())) {
            return;
        }
        if avt_ref && !matches!(want, JavaType::Object(_)) {
            return;
        }
        let slot = vt.var(*var).slot;
        let mut hits: Vec<u32> = Vec::new();
        for v in &vt.vars {
            if v.slot != slot || !top_ids.contains(&v.id) || v.id == *var {
                continue;
            }
            let t = v.ty.erased();
            let ok = match (&t, want) {
                (JavaType::Object(n), JavaType::Object(w)) => {
                    n.as_ref() == w.as_ref()
                        || pool.is_subtype(n.as_ref(), w.as_ref())
                }
                (JavaType::Array(_), JavaType::Array(_)) => want_arr,
                _ => false,
            };
            if ok {
                hits.push(v.id);
            }
        }
        hits.sort_unstable();
        hits.dedup();
        if hits.is_empty() {
            return;
        }
        // Multiple same-slot candidates: the LATEST generation (max id —
        // split mints in walk order ≈ program order) is the closest
        // approximation of the register's value at the use site. A
        // wrong pick still compiles (type-matched by construction);
        // leaving the primitive actual never does.
        let id = *hits.last().unwrap();
        *var = id;
        *ty = vt.vars[id as usize].ty.clone();
    };
    walk_stmt_exprs(body, &mut |e| {
        deep_rewrite(e, &mut |x| {
            match x {
                Expr::Method { desc, args, is_dynamic: false, .. } => {
                    for (i, a) in args.iter_mut().enumerate() {
                        if let Some(f) = desc.args.get(i) {
                            if matches!(f, JavaType::Object(n) if n.as_ref() != "java/lang/Object")
                                || matches!(f, JavaType::Array(_))
                            {
                                try_swap(a, f);
                            }
                        }
                    }
                }
                Expr::New { arg_tys, args, .. } => {
                    for (i, a) in args.iter_mut().enumerate() {
                        if let Some(f) = arg_tys.get(i) {
                            if matches!(f, JavaType::Object(n) if n.as_ref() != "java/lang/Object")
                                || matches!(f, JavaType::Array(_))
                            {
                                try_swap(a, f);
                            }
                        }
                    }
                }
                _ => {}
            }
        });
    });
    if ret_wants_ref {
        walk_mut_deep(body, &mut |st| {
            if let Stmt::Return(Some(e)) = st {
                try_swap(e, ret_ty);
            }
        });
    }
}

/// Reference-array initializers take null, not 0: dex fill-array-data
/// over a String[]/Object[] slot carries the zero word, and the lifted
/// `new String[] {0}` is int无法转换为String (qs0/b family). A Const
/// Int(0) element of a reference-typed array init is the null ref.
pub fn fix_ref_array_null_consts(body: &mut Stmt) {
    walk_stmt_exprs(body, &mut |e| {
        deep_rewrite(e, &mut |x| {
            if let Expr::NewArray { elem, init: Some(list), .. } = x {
                if matches!(elem.erased(), JavaType::Object(_) | JavaType::Array(_)) {
                    for slot in list.iter_mut() {
                        if matches!(&*slot, Expr::Const(ConstVal::Int(0))) {
                            *slot = Expr::Const(ConstVal::Null);
                        }
                    }
                }
            }
        });
    });
}

/// Int-context operand bridge: a BOOLEAN-typed side of an int-kind Bin
/// (bitwise, arithmetic, comparison against a numeric) becomes
/// `(b ? 1 : 0)` — the dex-level truth (booleans ARE 0/1 ints there;
/// register reuse puts a bool-typed var into an int expression:
/// `v5x | 4`, `b == 0` — "boolean无法转换为int" / "二元运算符操作数
/// 类型错误" families). Runs AFTER fix_bool_xor so boolean-SINK chains
/// were already converted to all-boolean form and are skipped here.
pub fn fix_int_operand_bridges(body: &mut Stmt, vt: &VarTable) {
    fn side_bool(e: &Expr, vt: &VarTable) -> bool {
        matches!(
            match e {
                Expr::Local { var, .. } => vt.var(*var).ty.erased(),
                other => other.type_ref().erased(),
            },
            JavaType::Boolean
        )
    }
    fn side_int(e: &Expr, vt: &VarTable) -> bool {
        matches!(
            match e {
                Expr::Local { var, .. } => vt.var(*var).ty.erased(),
                other => other.type_ref().erased(),
            },
            JavaType::Int | JavaType::Short | JavaType::Byte | JavaType::Char | JavaType::Long
        )
    }
    fn wrap(e: Box<Expr>) -> Box<Expr> {
        Box::new(Expr::Cond {
            c: e,
            t: Box::new(Expr::Const(ConstVal::Int(1))),
            f: Box::new(Expr::Const(ConstVal::Int(0))),
        })
    }
    walk_stmt_exprs(body, &mut |e| {
        deep_rewrite(e, &mut |x| {
            // Field / array-store positions: the target's type is
            // descriptor-backed (authoritative); a boolean value into
            // an int slot bridges `(b ? 1 : 0)` (with a narrowing cast
            // for byte/short/char slots), an int value into a boolean
            // slot bridges `v != 0` (weixin `this.L[v3x] = max3`,
            // `g2x.d = p1x` — 785 field + ~700 array lines).
            if let Expr::Assign { target, value, op: AssignOp::Plain } = x {
                let tgt_ty: Option<JavaType> = match &**target {
                    Expr::Field { ty, .. } => Some(ty.erased()),
                    Expr::ArrayIndex { array, .. } => {
                        match array.type_ref().erased() {
                            JavaType::Array(el) => Some(el.as_ref().clone()),
                            _ => None,
                        }
                    }
                    // Local targets: the split/booleanize machinery owns
                    // the mixed-kind register cases; the residue that
                    // reached render (boolean无法转换为byte/long, ~360
                    // lines) gets the same value-side bridge.
                    Expr::Local { var, .. } => {
                        if (*var as usize) < vt.vars.len() {
                            Some(vt.var(*var).ty.erased())
                        } else {
                            None
                        }
                    }
                    _ => None,
                };
                if let Some(t) = tgt_ty {
                    let tgt_int = matches!(
                        t,
                        JavaType::Int
                            | JavaType::Short
                            | JavaType::Byte
                            | JavaType::Char
                            | JavaType::Long
                    );
                    if tgt_int && side_bool(value, vt) && !side_int(value, vt) {
                        let taken = std::mem::replace(
                            value,
                            Box::new(Expr::Const(ConstVal::Null)),
                        );
                        let mut wrapped = wrap(taken);
                        if !matches!(t, JavaType::Int | JavaType::Long) {
                            wrapped = Box::new(Expr::Cast {
                                ty: TypeRef::J(t.clone()),
                                e: wrapped,
                            });
                        }
                        *value = wrapped;
                    } else if matches!(t, JavaType::Boolean)
                        && side_int(value, vt)
                        && !side_bool(value, vt)
                    {
                        let taken = std::mem::replace(
                            value,
                            Box::new(Expr::Const(ConstVal::Null)),
                        );
                        **value = Expr::Bin {
                            op: BinOp::Ne,
                            l: taken,
                            r: Box::new(Expr::Const(ConstVal::Int(0))),
                            ty: Some(TypeRef::J(JavaType::Boolean)),
                        };
                    }
                }
            }
            // Explicit casts across the bool/num line are invalid Java
            // in BOTH directions: `(byte) this.r` (dex int-to-byte over
            // a boolean-rendered field — weixin AccInfo writeByte ×207)
            // becomes `(byte)(r ? 1 : 0)`, and `(boolean) x` over an
            // int becomes `x != 0`.
            if let Expr::Cast { ty, e } = x {
                let t = ty.erased();
                let t_num = matches!(
                    t,
                    JavaType::Int
                        | JavaType::Short
                        | JavaType::Byte
                        | JavaType::Char
                        | JavaType::Long
                        | JavaType::Float
                        | JavaType::Double
                );
                if t_num && side_bool(e, vt) && !side_int(e, vt) {
                    let taken = std::mem::replace(e, Box::new(Expr::Const(ConstVal::Null)));
                    **e = Expr::Cond {
                        c: taken,
                        t: Box::new(Expr::Const(ConstVal::Int(1))),
                        f: Box::new(Expr::Const(ConstVal::Int(0))),
                    };
                } else if matches!(t, JavaType::Boolean)
                    && side_int(e, vt)
                    && !side_bool(e, vt)
                {
                    let taken = std::mem::replace(e, Box::new(Expr::Const(ConstVal::Null)));
                    *x = Expr::Bin {
                        op: BinOp::Ne,
                        l: taken,
                        r: Box::new(Expr::Const(ConstVal::Int(0))),
                        ty: Some(TypeRef::J(JavaType::Boolean)),
                    };
                }
            }
            // Null-vs-int comparison: dex if-eqz/if-nez is type-agnostic
            // and null IS zero — when the local came out int-typed (phi
            // confluence residue), rewrite the Null constant to 0
            // (`v95_g12 != null` → `v95_g12 != 0`, faithful and legal;
            // yq0/g1 546-line 二元运算符 family).
            if let Expr::Bin { op, l, r, .. } = x {
                if matches!(op, BinOp::Eq | BinOp::Ne) {
                    if matches!(&**r, Expr::Const(ConstVal::Null))
                        && side_int(l, vt)
                        && !side_bool(l, vt)
                    {
                        **r = Expr::Const(ConstVal::Int(0));
                    } else if matches!(&**l, Expr::Const(ConstVal::Null))
                        && side_int(r, vt)
                        && !side_bool(r, vt)
                    {
                        **l = Expr::Const(ConstVal::Int(0));
                    }
                }
            }
            // A boolean-typed array INDEX is a reused register holding
            // an int (`this.L[v3x]` — boolean无法转换为int at the index
            // position): bridge it in reads and writes alike.
            if let Expr::ArrayIndex { index, .. } = x {
                if side_bool(index, vt) && !side_int(index, vt) {
                    let taken =
                        std::mem::replace(index, Box::new(Expr::Const(ConstVal::Null)));
                    *index = wrap(taken);
                }
            }
            if let Expr::Bin { op, l, r, .. } = x {
                let int_kind = matches!(
                    op,
                    BinOp::Or
                        | BinOp::And
                        | BinOp::Xor
                        | BinOp::Add
                        | BinOp::Sub
                        | BinOp::Mul
                        | BinOp::Div
                        | BinOp::Rem
                        | BinOp::Shl
                        | BinOp::Shr
                        | BinOp::Ushr
                        | BinOp::Eq
                        | BinOp::Ne
                        | BinOp::Lt
                        | BinOp::Ge
                        | BinOp::Gt
                        | BinOp::Le
                );
                if !int_kind {
                    return;
                }
                // Comparisons only bridge against a NUMERIC constant or
                // int-typed side (a bool == bool compare is valid Java).
                if side_bool(l, vt) && side_int(r, vt) && !side_bool(r, vt) {
                    let taken = std::mem::replace(l, Box::new(Expr::Const(ConstVal::Null)));
                    *l = wrap(taken);
                } else if side_bool(r, vt) && side_int(l, vt) && !side_bool(l, vt) {
                    let taken = std::mem::replace(r, Box::new(Expr::Const(ConstVal::Null)));
                    *r = wrap(taken);
                }
            }
        });
    });
}

/// Statement-level idiom restoration (readability parity with
/// jadx/DAD, flagged by the androguard comparison): `v = v + 1` →
/// `v++`, `v = v op x` → `v op= x`. Local targets only — a compound
/// field/array target would change how often the receiver expression
/// evaluates. Var must be the LEFT operand (non-commutative ops;
/// string-concat order). The ±1 fold requires a numeric vt type
/// (`s++` on a String is invalid while `s += 1` is not).
pub fn idiom_compounds(body: &mut Stmt, vt: &VarTable) {
    walk_mut_deep(body, &mut |st| {
        let Stmt::ExprStmt(e) = st else { return };
        let Expr::Assign { target, op: AssignOp::Plain, value } = &mut *e else {
            return;
        };
        // Target: a local, or a bare field (static / this — no complex
        // receiver whose re-evaluation a compound would elide).
        enum Tgt {
            Loc(u32),
            Fld,
        }
        let tgt = match &**target {
            Expr::Local { var, .. } => Tgt::Loc(*var),
            Expr::Field { owner, .. }
                if owner.is_none()
                    || matches!(&**owner.as_ref().unwrap(), Expr::This) =>
            {
                Tgt::Fld
            }
            _ => return,
        };
        let Expr::Bin { op, l, r, .. } = &mut **value else {
            return;
        };
        // The left operand must be the SAME storage as the target.
        match (&tgt, &**l) {
            (Tgt::Loc(v), Expr::Local { var, .. }) if *var == *v => {}
            (Tgt::Fld, Expr::Field { cls: c2, name: n2, .. }) => {
                let Expr::Field { cls: c1, name: n1, .. } = &**target else {
                    return;
                };
                if c1 != c2 || n1 != n2 {
                    return;
                }
            }
            _ => return,
        }
        // ±1 constant on a numeric var → post-inc/dec.
        let one = match &**r {
            Expr::Const(ConstVal::Int(1)) => Some(1i64),
            Expr::Const(ConstVal::Int(-1)) => Some(-1),
            Expr::Const(ConstVal::Long(1)) => Some(1),
            Expr::Const(ConstVal::Long(-1)) => Some(-1),
            _ => None,
        };
        if *op == BinOp::Add || *op == BinOp::Sub {
            if let Some(mut d) = one {
                if *op == BinOp::Sub {
                    d = -d;
                }
                let tgt_ty = match &tgt {
                    Tgt::Loc(v) => vt.var(*v).ty.erased(),
                    Tgt::Fld => {
                        let Expr::Field { ty, .. } = &**target else {
                            return;
                        };
                        ty.erased()
                    }
                };
                let numeric = matches!(
                    tgt_ty,
                    JavaType::Int
                        | JavaType::Long
                        | JavaType::Short
                        | JavaType::Byte
                        | JavaType::Char
                        | JavaType::Float
                        | JavaType::Double
                );
                if numeric {
                    let wide = matches!(tgt_ty, JavaType::Long);
                    let inner = match &tgt {
                        Tgt::Loc(v) => Expr::Local {
                            var: *v,
                            ty: vt.var(*v).ty.clone(),
                        },
                        Tgt::Fld => (**target).clone(),
                    };
                    *e = Expr::PostIncDec {
                        e: Box::new(inner),
                        delta: d,
                        wide,
                    };
                    return;
                }
            }
        }
        let cop = match op {
            BinOp::Add => AssignOp::Add,
            BinOp::Sub => AssignOp::Sub,
            BinOp::Mul => AssignOp::Mul,
            BinOp::Div => AssignOp::Div,
            BinOp::Rem => AssignOp::Rem,
            BinOp::Shl => AssignOp::Shl,
            BinOp::Shr => AssignOp::Shr,
            BinOp::Ushr => AssignOp::Ushr,
            BinOp::And => AssignOp::And,
            BinOp::Or => AssignOp::Or,
            BinOp::Xor => AssignOp::Xor,
            _ => return,
        };
        let rhs = std::mem::replace(r, Box::new(Expr::Const(ConstVal::Null)));
        let new_target = match &tgt {
            Tgt::Loc(v) => Box::new(Expr::Local {
                var: *v,
                ty: vt.var(*v).ty.clone(),
            }),
            Tgt::Fld => target.clone(),
        };
        *e = Expr::Assign {
            target: new_target,
            op: cop,
            value: rhs,
        };
    });
}

pub fn fix_bool_xor(body: &mut Stmt, vt: &VarTable, ret_bool: bool) {
    fn is_one(e: &Expr) -> bool {
        matches!(e, Expr::Const(ConstVal::Int(1)))
    }
    fn bty(e: &Expr, vt: &VarTable) -> bool {
        matches!(
            match e {
                Expr::Local { var, .. } => vt.var(*var).ty.erased(),
                other => other.type_ref().erased(),
            },
            JavaType::Boolean
        )
    }
    // Int-typed `x ^ 1` in a BOOLEAN sink is the compiler's `!x` over a
    // 0/1 slot: rewrite to `x == 0` (the booleanize return-wrap misses
    // Xor shapes — weibo ArraysKt `return v2 ^ 1;` against a boolean
    // return, "int无法转换为boolean").
    fn inv_of_xor(x: &Expr, vt: &VarTable) -> Option<Expr> {
        if let Expr::Bin { op: BinOp::Xor, l, r, .. } = x {
            let (int_side, one_side) = if is_one(r) {
                (l, r)
            } else if is_one(l) {
                (r, l)
            } else {
                return None;
            };
            let _ = one_side;
            if !bty(int_side, vt) {
                return Some(Expr::Bin {
                    op: BinOp::Eq,
                    l: int_side.clone(),
                    r: Box::new(Expr::Const(ConstVal::Int(0))),
                    ty: Some(TypeRef::J(JavaType::Boolean)),
                });
            }
        }
        None
    }
    let tgt_bool = |target: &Expr, vt: &VarTable| -> bool {
        match target {
            Expr::Local { var, .. } => matches!(vt.var(*var).ty.erased(), JavaType::Boolean),
            Expr::Field { ty, .. } => matches!(ty.erased(), JavaType::Boolean),
            _ => false,
        }
    };
    walk_mut_deep(body, &mut |st| match st {
        Stmt::Return(Some(e)) if ret_bool => {
            if let Some(r) = inv_of_xor(e, vt) {
                *e = r;
            }
        }
        Stmt::ExprStmt(Expr::Assign { target, value, op: AssignOp::Plain, .. }) => {
            if tgt_bool(target, vt) {
                if let Some(r) = inv_of_xor(value, vt) {
                    **value = r;
                }
            }
        }
        Stmt::LocalDef { var, init: Some(value), .. }
            if matches!(vt.var(*var).ty.erased(), JavaType::Boolean) =>
        {
            if let Some(r) = inv_of_xor(value, vt) {
                *value = r;
            }
        }
        Stmt::If { cond, .. } | Stmt::While { cond, .. } | Stmt::DoWhile { cond, .. } => {
            if let Some(r) = inv_of_xor(cond, vt) {
                *cond = r;
            }
        }
        _ => {}
    });
    fn ity(e: &Expr, vt: &VarTable) -> bool {
        matches!(
            match e {
                Expr::Local { var, .. } => vt.var(*var).ty.erased(),
                other => other.type_ref().erased(),
            },
            JavaType::Int | JavaType::Short | JavaType::Byte | JavaType::Char
        )
    }
    /// Mixed-kind bitwise rewrite: Kotlin's non-short-circuit
    /// `or`/`and` over 0/1 ints mixes generations once booleanize
    /// converts one side (`delete | delete2` — "boolean无法转换为int" at
    /// the OPERAND, weixin SQLiteDatabase ×3.3k), and `b ^ 1` is `!b`.
    /// The int side is a 0/1 encoding: compare it, keeping the chain
    /// boolean end to end. ONLY legal into a BOOLEAN sink — ungated, it
    /// rewrote int-sink `v6 = v5x | 4` into `v5x | 4 != 0` assigned to
    /// an int var (boolean无法转换为int, weixin yq5/c ×2.1k family).
    fn mixed_rewrite(e: &mut Expr, vt: &VarTable) {
        deep_rewrite(e, &mut |x| {
            if let Expr::Bin { op, l, r, ty } = x {
                match op {
                    BinOp::Xor => {
                        if is_one(r) && bty(l, vt) {
                            let taken =
                                std::mem::replace(l, Box::new(Expr::Const(ConstVal::Null)));
                            *x = Expr::Un { op: UnOp::Not, e: taken };
                        } else if is_one(l) && bty(r, vt) {
                            let taken =
                                std::mem::replace(r, Box::new(Expr::Const(ConstVal::Null)));
                            *x = Expr::Un { op: UnOp::Not, e: taken };
                        }
                    }
                    BinOp::Or | BinOp::And => {
                        if bty(l, vt) && ity(r, vt) {
                            let taken =
                                std::mem::replace(r, Box::new(Expr::Const(ConstVal::Null)));
                            **r = Expr::Bin {
                                op: BinOp::Ne,
                                l: taken,
                                r: Box::new(Expr::Const(ConstVal::Int(0))),
                                ty: Some(TypeRef::J(JavaType::Boolean)),
                            };
                            *ty = Some(TypeRef::J(JavaType::Boolean));
                        } else if ity(l, vt) && bty(r, vt) {
                            let taken =
                                std::mem::replace(l, Box::new(Expr::Const(ConstVal::Null)));
                            **l = Expr::Bin {
                                op: BinOp::Ne,
                                l: taken,
                                r: Box::new(Expr::Const(ConstVal::Int(0))),
                                ty: Some(TypeRef::J(JavaType::Boolean)),
                            };
                            *ty = Some(TypeRef::J(JavaType::Boolean));
                        }
                    }
                    _ => {}
                }
            }
        });
    }
    // Boolean sinks: bool-typed assign/def targets, boolean-method
    // returns, and loop/branch conditions.
    walk_mut_deep(body, &mut |st| match st {
        Stmt::Return(Some(e)) if ret_bool => mixed_rewrite(e, vt),
        Stmt::ExprStmt(Expr::Assign { target, value, op: AssignOp::Plain, .. }) => {
            if tgt_bool(target, vt) {
                mixed_rewrite(value, vt);
            }
        }
        Stmt::LocalDef { var, init: Some(e), .. }
            if matches!(vt.var(*var).ty.erased(), JavaType::Boolean) =>
        {
            mixed_rewrite(e, vt);
        }
        Stmt::If { cond, .. } | Stmt::While { cond, .. } | Stmt::DoWhile { cond, .. } => {
            mixed_rewrite(cond, vt);
        }
        _ => {}
    });
    // A conditional's test is a boolean sink wherever it sits (including
    // inside int-sink statements the walk above skips).
    walk_stmt_exprs(body, &mut |e| {
        deep_rewrite(e, &mut |x| {
            if let Expr::Cond { c, .. } = x {
                mixed_rewrite(c, vt);
            }
        });
    });
}

/// Boolean inference: vars only ever assigned 0/1/comparisons/booleans and
/// read in conditions become `boolean`, with `v != 0` → `v` in conditions.
/// Returns the number of vars converted (0 = nothing changed — the
/// caller skips the post-booleanize re-split, which only has work when
/// a conversion exposed a mixed-kind register).
pub fn booleanize(vt: &mut VarTable, body: &mut Stmt, ret_bool: bool) -> usize {
    // Booleans propagate through local chains (`v17 = v24` where v24
    // itself became boolean in the first round) — iterate to a fixpoint;
    // the common corpus converts nothing and exits after one round.
    // The deref disqualifier set is structural (positions, not types) —
    // compute ONCE per call, not per round (12 full walks on big
    // methods cost weibo +60% wall).
    let n0 = vt.vars.len();
    let mut derefed = vec![false; n0];
    mark_derefs(body, &mut derefed);
    let mut total = 0usize;
    for _ in 0..4 {
        let n = booleanize_round(vt, body, ret_bool, &derefed);
        if n == 0 {
            break;
        }
        total += n;
    }
    total
}

/// Mark vars used in DEREF positions (field/method receiver, array
/// base) — allocation-free recursion (visit_all_exprs allocates a
/// child Vec per statement; two callers run this per method).
fn mark_deref_expr(e: &Expr, derefed: &mut [bool]) {
    match e {
        Expr::Field { owner: Some(o), is_static: false, .. }
        | Expr::Method { owner: Some(o), .. } => {
            if let Expr::Local { var, .. } = &**o {
                if (*var as usize) < derefed.len() {
                    derefed[*var as usize] = true;
                }
            }
        }
        Expr::ArrayIndex { array, .. } => {
            if let Expr::Local { var, .. } = &**array {
                if (*var as usize) < derefed.len() {
                    derefed[*var as usize] = true;
                }
            }
        }
        _ => {}
    }
    for_each_child(e, &mut |c| mark_deref_expr(c, derefed));
}

fn mark_derefs(body: &Stmt, derefed: &mut [bool]) {
    walk_all(body, &mut |st| {
        match st {
            Stmt::ExprStmt(e) | Stmt::Throw(e) | Stmt::MonitorEnter(e) | Stmt::MonitorExit(e) => {
                mark_deref_expr(e, derefed);
            }
            Stmt::Return(Some(e)) => mark_deref_expr(e, derefed),
            Stmt::LocalDef { init: Some(e), .. } => mark_deref_expr(e, derefed),
            Stmt::If { cond, .. } | Stmt::While { cond, .. } | Stmt::DoWhile { cond, .. } => {
                mark_deref_expr(cond, derefed);
            }
            Stmt::For { init, .. } => {
                for x in init {
                    mark_derefs(x, derefed);
                }
            }
            Stmt::Switch { selector, .. } => mark_deref_expr(selector, derefed),
            Stmt::ForEach { iterable, .. } => mark_deref_expr(iterable, derefed),
            _ => {}
        }
    });
}

fn booleanize_round(
    vt: &mut VarTable,
    body: &mut Stmt,
    ret_bool: bool,
    derefed: &[bool],
) -> usize {
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
        // A local RETURNED from a boolean method is boolean-typed even
        // though it never appears in a condition (`int v9 = 0/1 … return
        // v9;` — returning an int from `boolean check()` is a compile
        // error; lab package Obf.check).
        if ret_bool {
            if let Stmt::Return(Some(Expr::Local { var, .. })) = st {
                if (*var as usize) < n {
                    in_cond[*var as usize] = true;
                }
            }
        }
        // A local STORED into a boolean field is boolean-typed even though
        // it never appears in a condition (`b = v1` where `b` is a boolean
        // field, `v1` an int 0/1 local — q.java static init). The emit
        // layer already coerces a boolean-target assign through expr_bool,
        // but that renders a bare int LOCAL unchanged, so the local itself
        // must be booleanized (its 0/1 assigns then print false/true).
        if let Stmt::ExprStmt(Expr::Assign { target, value, .. }) = st {
            if let Expr::Field { ty, .. } = &**target {
                if ty.erased() == JavaType::Boolean {
                    if let Expr::Local { var, .. } = &**value {
                        if (*var as usize) < n {
                            in_cond[*var as usize] = true;
                        }
                    }
                }
            }
        }
        let val: Option<&Expr> = match st {
            Stmt::ExprStmt(Expr::Assign { value, .. }) => Some(value),
            // Bare expression statements (e.g. `q(v117);`) so a local
            // passed to a boolean parameter is caught below.
            Stmt::ExprStmt(e) => Some(e),
            Stmt::LocalDef { init: Some(e), .. } => Some(e),
            Stmt::Return(Some(e)) => Some(e),
            _ => None,
        };
        if let Some(v) = val {
            visit_exprs(v, &mut |x| {
                // A local passed as a BOOLEAN parameter is boolean-typed
                // (`q(v117)` where q's param is boolean, v117 an int 0/1 —
                // f8/b.java). The DEX passes booleans as 0/1 ints, so a
                // boolean param slot is authoritative for the argument's
                // type.
                if let Expr::Method { desc, args, .. } = x {
                    for (i, a) in args.iter().enumerate() {
                        if desc.args.get(i) == Some(&JavaType::Boolean) {
                            if let Expr::Local { var, .. } = a {
                                if (*var as usize) < n {
                                    in_cond[*var as usize] = true;
                                }
                            }
                        }
                    }
                }
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
                    // Kotlin/d8 merge booleans through INT bitwise ops
                    // (`v3 | obj instanceof g`) == 0 — the other side's
                    // static type being boolean makes this a boolean
                    // context for the local (a genuine int bitwise
                    // expression never has a boolean operand).
                    if matches!(op, BinOp::Or | BinOp::And) {
                        let l_bool = l.type_ref().erased() == JavaType::Boolean;
                        let r_bool = r.type_ref().erased() == JavaType::Boolean;
                        if l_bool != r_bool {
                            let side = if l_bool { r } else { l };
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
    let mut edges: Vec<(usize, usize)> = Vec::new();
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
            if !is_boolean_valued(value, vt) {
                all_bool[i] = false;
            }
            // Chain edges for the context closure below: `v17 = v24`
            // links the two locals; when the TARGET is in a boolean
            // context, the source inherits it (its only reader is the
            // boolean-shaped chain). Collected as edges because the
            // target's context can be discovered anywhere in the tree.
            if let Expr::Local { var: src, .. } = value {
                if (*src as usize) < n {
                    edges.push((i, *src as usize));
                }
            }
        }
    });
    // Context closure along local chains: a var in a boolean context
    // pushes that context through every local it is assigned from
    // (`return v17` — v17 = v24 — v24 = 0/1) — the statement order
    // cannot be relied on (the return may follow the assignment).
    loop {
        let mut changed = false;
        for &(tgt, src) in &edges {
            if in_cond[tgt] && !in_cond[src] && all_bool[src] {
                in_cond[src] = true;
                changed = true;
            }
            // FORWARD through pure copies: `v21 = v17` with v17 boolean
            // makes v21 boolean when ALL of v21's assignments are
            // bool-shaped (the loop-state save pattern — weixin u2/f's
            // v62 → v17 → v21 chains left the copy targets int while
            // the accumulator booleanized).
            if in_cond[src] && !in_cond[tgt] && all_bool[tgt] {
                in_cond[tgt] = true;
                changed = true;
            }
        }
        if !changed {
            break;
        }
    }
    let reads = count_locals_stmts(std::slice::from_ref(body));
    let mut boolean_vars: HashSet<u32> = HashSet::default();
    for i in 0..n {
        if vt.vars[i].is_param {
            continue;
        }
        if derefed[i] {
            continue;
        }
        if !in_cond[i] && !(reads.get(&(i as u32)).copied().unwrap_or(0) == 0) {
            continue;
        }
        if assigned_any[i] && all_bool[i] {
            boolean_vars.insert(i as u32);
        }
    }
    if boolean_vars.is_empty() {
        return 0;
    }
    for v in &boolean_vars {
        vt.vars[*v as usize].ty = TypeRef::J(JavaType::Boolean);
    }
    let types: Vec<&TypeRef> = vt.vars.iter().map(|v| &v.ty).collect();
    rewrite_exprs(body, &mut |e| {
        deep_rewrite(e, &mut |x| {
            if let Expr::Local { var, ty } = x {
                if let Some(want) = types.get(*var as usize) {
                    if ty != *want {
                        *ty = (*want).clone();
                    }
                }
            }
        });
    });

    // Condition folding: `b != 0` → `b`, `b == 0` → `!b` (boolean vars).
    fold_bool_conditions(body, &boolean_vars);
    boolean_vars.len()
}

fn is_boolean_valued(e: &Expr, vt: &VarTable) -> bool {
    match e {
        Expr::Const(ConstVal::Int(0)) | Expr::Const(ConstVal::Int(1)) => true,
        // Kotlin's non-short-circuit boolean `or`/`and` compiles to `|`/`&`
        // over boolean locals (`v15 = delete | delete2 | ..`). EITHER side
        // boolean suffices: `int | boolean` is illegal in source — it is
        // always a not-yet-booleanized side of a boolean chain (the
        // loop-carried accumulator `v15 = v20; v20 = v15 | delete3` can
        // never seed its all_bool fixpoint otherwise).
        Expr::Bin { op: BinOp::Or | BinOp::And, l, r, .. } => {
            is_boolean_valued(l, vt) || is_boolean_valued(r, vt)
        }
        // Kotlin's `!x` lowers to `x ^ 1`; at booleanize time the value
        // is still the Xor (fix_bool_xor runs later), so an int-typed
        // generation receiving it never retyped (weixin v2/i's
        // `int v264_g160_g7 = !v200`). BOTH sides must be bool-shaped:
        // `bool ^ 1` qualifies (Const 0/1 is boolean-valued above),
        // a genuine int `flags ^ 1` does not (flags stays Int in vt).
        // MUST precede the generic Bin arm (which would swallow Xor).
        Expr::Bin {
            op: BinOp::Xor,
            l,
            r,
            ..
        } => is_boolean_valued(l, vt) && is_boolean_valued(r, vt),
        Expr::Bin { op, .. } => matches!(
            op,
            BinOp::Eq | BinOp::Ne | BinOp::Lt | BinOp::Ge | BinOp::Gt | BinOp::Le
        ),
        Expr::InstanceOf { .. } => true,
        // The VarTable is the authority: the embedded Local ty is a
        // lift-time snapshot and goes STALE across booleanize rounds —
        // a converted copy source kept its partners int (`v150 = v131`
        // boolean→int, weixin ConstraintLayout ×1.4k files) because the
        // all_bool fixpoint consulted the stale Int.
        Expr::Local { var, ty } => {
            let t = if (*var as usize) < vt.vars.len() {
                vt.var(*var).ty.erased()
            } else {
                ty.erased()
            };
            t == JavaType::Boolean
        }
        Expr::Method { desc, .. } => desc.ret == JavaType::Boolean,
        Expr::Cond { t, f, .. } => is_boolean_valued(t, vt) && is_boolean_valued(f, vt),
        Expr::Un { op: UnOp::Not, .. } => true,
        // Field ty comes from the dex descriptor — authoritative, not a
        // lift snapshot (`!w1x.i` arrives here still as `w1x.i ^ 1`; the
        // Xor arm needs this side bool-shaped).
        Expr::Field { ty, .. } => ty.erased() == JavaType::Boolean,
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
    rewrite_exprs(body, &mut |e| {
        deep_rewrite(e, &mut |x| {
            null_side_rewrite(x, &|v| obj_vars.contains(&v));
        });
    });
}

/// Drop assignments/declarations of locals that are NEVER read anywhere
/// in the method. Register-machine merges commit values no Java-level
/// code consumes (phi residue like `printStream = check;` — not just
/// noise: the merge variable's inferred type need not match the value,
/// so these lines are often type errors as well). Side-effect-free
/// values drop entirely; an impure value survives as a bare expression
/// statement. Iterated to a fixpoint: dropping `a = b` can make `b`
/// unread.
pub fn drop_dead_locals(body: &mut Stmt) {
    loop {
        let mut reads: Vec<usize> = Vec::new();
        count_reads(body, &mut reads);
        let mut dropped = 0usize;
        walk_mut_deep(body, &mut |st| match st {
            Stmt::Block(items) => prune_dead_items(items, &reads, &mut dropped),
            // Switch case bodies and For inits are bare `Vec<Stmt>`, NOT
            // wrapped in a `Stmt::Block`, so the Block arm never sees them.
            // Dead phi commits land directly in case bodies (`sb4 =
            // compareTo;` per case): pruning only Blocks dropped the
            // commit's reader (in a real post-switch Block) but left the
            // now-dead commits, stalling the fixpoint cascade and leaking
            // mistyped phi residue. TryWithResources.resources is
            // deliberately excluded — its LocalDefs carry auto-close
            // semantics that a bare-expression rewrite would break.
            Stmt::Switch { cases, .. } => {
                for c in cases {
                    prune_dead_items(&mut c.body, &reads, &mut dropped);
                }
            }
            Stmt::For { init, .. } => prune_dead_items(init, &reads, &mut dropped),
            _ => {}
        });
        if dropped == 0 {
            break;
        }
    }
}

/// Remove dead assignments/declarations from one bare statement vector.
/// Shared by `drop_dead_locals` across every prunable `Vec<Stmt>`
/// container. Side-effect-free values drop entirely; an impure value
/// survives as a bare expression statement.
fn prune_dead_items(items: &mut Vec<Stmt>, reads: &[usize], dropped: &mut usize) {
    let dead = |v: u32| reads.get(v as usize).copied().unwrap_or(0) == 0;
    items.retain_mut(|x| match x {
        Stmt::ExprStmt(Expr::Assign { target, value, op, .. }) => {
            let dead_target = matches!(&**target, Expr::Local { var, .. } if dead(*var));
            if dead_target && matches!(*op, AssignOp::Plain) {
                *dropped += 1;
                if has_side_effects(value) {
                    let e = std::mem::replace(value, Box::new(Expr::This));
                    *x = Stmt::ExprStmt(*e);
                    true
                } else {
                    false
                }
            } else {
                true
            }
        }
        Stmt::LocalDef { var, init, .. } if dead(*var) => {
            *dropped += 1;
            if let Some(e) = init.take() {
                if has_side_effects(&e) {
                    *x = Stmt::ExprStmt(e);
                    return true;
                }
            }
            false
        }
        _ => true,
    });
}

/// Immutable shallow child walk (mirrors `walk_mut`), for the two-pass
/// scope analysis below.
fn for_each_child_stmt<'a>(st: &'a Stmt, f: &mut impl FnMut(&'a Stmt)) {
    match st {
        Stmt::Block(v) => {
            for x in v {
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
            for x in init {
                f(x);
            }
            f(body);
        }
        Stmt::ForEach { body, .. } => f(body),
        Stmt::Switch { cases, default, .. } => {
            for c in cases {
                for x in &c.body {
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
                f(&c.body);
            }
            if let Some(fl) = finally {
                f(fl);
            }
        }
        Stmt::TryWithResources {
            resources,
            body,
            catches,
            finally,
        } => {
            for r in resources {
                f(r);
            }
            f(body);
            for c in catches {
                f(&c.body);
            }
            if let Some(fl) = finally {
                f(fl);
            }
        }
        Stmt::Synchronized { body, .. } | Stmt::Labeled { body, .. } => f(body),
        _ => {}
    }
}

/// Vars occurring in this statement's OWN expression payloads (nested
/// sub-statements are descended separately so every occurrence carries
/// its innermost block id). ForEach/Catch bound vars are declarations,
/// not occurrences.
fn stmt_shallow_vars<F: FnMut(u32)>(st: &Stmt, out: &mut F) {
    fn ex<F: FnMut(u32)>(e: &Expr, out: &mut F) {
        visit_exprs(e, &mut |x| {
            if let Expr::Local { var, .. } = x {
                out(*var);
            }
        });
    }
    match st {
        Stmt::ExprStmt(e) | Stmt::Throw(e) | Stmt::MonitorEnter(e) | Stmt::MonitorExit(e) => {
            ex(e, out)
        }
        Stmt::TernaryValue { e } => ex(e, out),
        Stmt::Return(Some(e)) => ex(e, out),
        Stmt::LocalDef { var, init, .. } => {
            out(*var);
            if let Some(e) = init {
                ex(e, out);
            }
        }
        Stmt::If { cond, .. } | Stmt::While { cond, .. } | Stmt::DoWhile { cond, .. } => {
            ex(cond, out)
        }
        Stmt::For { cond, update, .. } => {
            if let Some(c) = cond {
                ex(c, out);
            }
            for u in update {
                ex(u, out);
            }
        }
        Stmt::ForEach { iterable, .. } => ex(iterable, out),
        Stmt::Switch { selector, cases, .. } => {
            ex(selector, out);
            for cg in cases {
                if let Some(g) = &cg.guard {
                    ex(g, out);
                }
            }
        }
        Stmt::Assert { cond, msg } => {
            ex(cond, out);
            if let Some(m) = msg {
                ex(m, out);
            }
        }
        Stmt::Synchronized { lock, .. } => ex(lock, out),
        _ => {}
    }
}

/// Pass A: number every Block in pre-order (root = 0) and record each
/// var's defining block. `sizes[id]` = the id-range span of the subtree.
fn scope_pass_a(st: &Stmt, cur: u32, next: &mut u32, def_block: &mut [u32], sizes: &mut Vec<u32>) {
    if let Stmt::LocalDef { var, .. } = st {
        let i = *var as usize;
        if i < def_block.len() && def_block[i] == u32::MAX {
            def_block[i] = cur;
        }
    }
    for_each_child_stmt(st, &mut |c| {
        if matches!(c, Stmt::Block(_)) {
            let id = *next;
            *next += 1;
            sizes.push(0);
            scope_pass_a(c, id, next, def_block, sizes);
            sizes[id as usize] = *next - id;
        } else {
            scope_pass_a(c, cur, next, def_block, sizes);
        }
    });
}

/// Pass B (same numbering walk): count each var's occurrences overall
/// and within its defining block's subtree.
fn scope_pass_b(
    st: &Stmt,
    cur: u32,
    next: &mut u32,
    def_block: &[u32],
    sizes: &[u32],
    within: &mut [u32],
    total: &mut [u32],
) {
    stmt_shallow_vars(st, &mut |v| {
        let i = v as usize;
        if i < total.len() {
            total[i] += 1;
            let d = def_block[i];
            if d != u32::MAX && d <= cur && cur < d + sizes[d as usize] {
                within[i] += 1;
            }
        }
    });
    for_each_child_stmt(st, &mut |c| {
        if matches!(c, Stmt::Block(_)) {
            let id = *next;
            *next += 1;
            scope_pass_b(c, id, next, def_block, sizes, within, total);
        } else {
            scope_pass_b(c, cur, next, def_block, sizes, within, total);
        }
    });
}

/// Declaration hygiene: every used var that has no LocalDef gets a bare
/// declaration at the top; duplicate LocalDefs demote to assignments.
/// In an enum's `<clinit>`, every constant's assignment
/// (`Self.FIELD = new Self("NAME", ordinal, ...)`) is compiler-mandated
/// boilerplate — when the class renders as a true `enum` declaration the
/// constants live in the header and these assignments must go. Only
/// ACC_ENUM-flagged static fields of the class itself are touched; the
/// `$VALUES` array assignment stays (a static block in an enum is legal).
pub fn strip_enum_const_inits(s: &mut Stmt, class: &crate::PoolClass) {
    let const_fields: jdc_core::FxHashSet<&str> = class
        .static_fields
        .iter()
        .filter(|f| f.access & crate::access::ACC_ENUM != 0)
        .map(|f| f.name.as_str())
        .collect();
    if const_fields.is_empty() {
        return;
    }
    if let Stmt::Block(stmts) = s {
        stmts.retain(|st| {
            !matches!(
                st,
                Stmt::ExprStmt(Expr::Assign { target, value, .. })
                    if matches!(&**target,
                        Expr::Field { cls, name, is_static: true, .. }
                            if cls.as_ref() == class.name
                                && const_fields.contains(&**name))
                        && matches!(&**value, Expr::New { cls: ncls, .. } if ncls.as_ref() == class.name)
            )
        });
    }
}

/// Java requires the `super(...)`/`this(...)` delegation to be the FIRST
/// statement of a constructor. d8/R8 order the outer-reference capture
/// (`this.b = p1;`) or other field writes before the invokesuper in the
/// bytecode, which lifts as-is into an uncompilable statement order —
/// hoist the bare delegation call to position 0 (jadx does the same).
pub fn fix_ctor_super_first(body: &mut Stmt) {
    let Stmt::Block(stmts) = body else { return };
    if stmts.is_empty() || is_bare_ctor_call(stmts.first().unwrap()) {
        return;
    }
    // Top-level delegation call.
    if let Some(pos) = stmts.iter().position(is_bare_ctor_call) {
        let call = stmts.remove(pos);
        stmts.insert(0, call);
        return;
    }
    // The structurer can wrap the delegation in a bare nested block —
    // with the parameter null-checks AHEAD of it (weixin's Kotlin
    // intrinsics shape: `o.h(parcel, "source"); super();` at inner
    // positions 0/1, flattened to straight-line by cleanup AFTER this
    // pass, which is why the miss surfaced as 1150 weixin "对super的
    // 调用必须是构造器中的第一个语句"). Hoist the call from any
    // position whose predecessors are all straight-line statements; a
    // delegation behind control flow is the conditional-super family
    // (needs restructuring, not hoisting) and stays put.
    let mut found: Option<(usize, usize)> = None;
    for (i, st) in stmts.iter().enumerate() {
        if let Stmt::Block(inner) = st {
            if let Some(p) = inner.iter().position(is_bare_ctor_call) {
                if inner[..p]
                    .iter()
                    .all(|s| matches!(s, Stmt::LocalDef { .. } | Stmt::ExprStmt(_)))
                {
                    found = Some((i, p));
                    break;
                }
            }
        }
    }
    if let Some((i, p)) = found {
        let call = match &mut stmts[i] {
            Stmt::Block(inner) => inner.remove(p),
            _ => unreachable!(),
        };
        stmts.insert(0, call);
    }
}

/// A true constructor DELEGATION statement: `super(..)` (owner None) or
/// `this(..)` (owner This). An un-folded `new X; <init>` (lost
/// allocation — the ctor-fold-bug family) arrives as a `<init>` Method
/// with a NON-this owner and prints as `new X(..)`: it is not a
/// delegation and must neither satisfy nor anchor the super-first fixes
/// (v7.a$a2: a dead `new f(0,..)` init at position 0 made both hoists
/// believe the delegation was already first, leaving the real `super`
/// last — "对super的调用必须是构造器中的第一个语句").
fn is_delegation_expr(e: &Expr) -> bool {
    matches!(
        e,
        Expr::Method { name, is_special: true, owner, .. }
            if &**name == "<init>"
                && (owner.is_none() || matches!(owner.as_deref(), Some(Expr::This)))
    )
}

fn is_bare_ctor_call(s: &Stmt) -> bool {
    matches!(s, Stmt::ExprStmt(e) if is_delegation_expr(e))
}

/// Is the local ever ASSIGNED (write position: `x = ..`, `++x`)?
/// Distinct from a read count: a ctor's synthetic outer param is only
/// ever read; a param that gets written must stay declared.
pub(crate) fn local_is_written(body: &Stmt, var: u32) -> bool {
    let mut hit = false;
    let mut c = body.clone();
    walk_stmt_exprs(&mut c, &mut |e| {
        if !hit {
            deep_rewrite(e, &mut |x| {
                if hit {
                    return;
                }
                match x {
                    Expr::Assign { target, .. }
                        if matches!(&**target, Expr::Local { var: v, .. } if *v == var) =>
                    {
                        hit = true;
                    }
                    Expr::PreIncDec { e, .. } | Expr::PostIncDec { e, .. }
                        if matches!(&**e, Expr::Local { var: v, .. } if *v == var) =>
                    {
                        hit = true;
                    }
                    _ => {}
                }
            });
        }
    });
    hit
}

/// Source-form normalization for a non-static member-inner constructor.
/// The dex descriptor carries the synthetic outer instance as args[0]
/// (typed as the direct enclosing class); the emitter's qualified
/// `outer.new Inner(..)` / `this.new Inner(..)` sites pass it
/// implicitly and `super(..)` delegations drop it, so the signature
/// loses the param — and the body must stop referencing it: plain uses
/// become `Outer.this` (a `this.this$0 = p` assignment becomes
/// `this.this$0 = Outer.this`, exactly the runtime value), and
/// this()-delegations to `eligible` classes drop the leading param arg.
pub(crate) fn rewrite_inner_ctor_outer_param(
    body: &mut Stmt,
    param0: u32,
    outer_display: &str,
    outer_ty: &TypeRef,
    eligible: &[String],
) {
    // this()/super() delegations (and lost-alloc construction calls):
    // the leading arg IS the synthetic outer exactly when it is the
    // param itself.
    walk_stmt_exprs(body, &mut |e| {
        if let Expr::Method { name, cls, args, .. } = e {
            if &**name == "<init>"
                && eligible.iter().any(|c| c.as_str() == cls.as_ref())
                && args.first().is_some_and(|a| matches!(a, Expr::Local { var: v, .. } if *v == param0))
            {
                args.remove(0);
            }
        }
    });
    // Every remaining read of the param becomes `Outer.this`.
    let text = format!("{outer_display}.this");
    let ty = outer_ty.clone();
    walk_stmt_exprs(body, &mut |e| {
        deep_rewrite_reads(e, &mut |x| {
            if let Expr::Local { var: v, .. } = x {
                if *v == param0 {
                    *x = Expr::RawT(text.clone(), ty.clone());
                }
            }
        });
    });
}

/// Ctors whose delegation is buried in control flow or behind arg
/// computations — the "对super的调用必须是构造器中的第一个语句" family
/// that plain hoisting cannot reach (weixin 264 / weibo 116 / reqable 71
/// / lark 62 after round 60): R8/Kotlin compute super-args conditionally
/// and dex legally invokes super mid-branch.
///
/// Shape B (branch merge): `prelude; if (c) {d1; super(A1); t1} else
/// {d2; super(A2); t2}; post` → one leading `super(..)` where each
/// differing arg becomes `c ? a1i : a2i`; branch remainders stay an
/// if/else AFTER the call; prelude statements move after it (nothing
/// may precede super in Java; bytecode pre-super work is local-only by
/// construction — dex forbids instance-field reads before the delegate).
///
/// Shape A (linear): `defs; super(A); rest` where `A` references the
/// def locals — plain hoisting (fix_ctor_super_first case 1) would move
/// the call above its argument definitions (forward refs). Inline the
/// referenced defs into the args first, drop the consumed defs, hoist.
/// Runs BEFORE fix_ctor_super_first and only fires when args reference
/// preceding locals, leaving the battle-tested plain hoist untouched
/// otherwise.
///
/// Inlining duplicates the def per use site, so a side-effecting def is
/// inlined only when its var's use count is provably preserved: a
/// single use in a merged arg (1 copy), or a single use in the
/// condition with ≤1 differing arg (the cond then appears in the `if`
/// plus one ternary — 2 copies of e.g. one Kotlin getter call, which
/// the original bytecode typically made twice anyway: `p.u() == null ?
/// .. : p.u().i()`). Pure defs inline freely. Every other shape aborts:
/// broken-but-faithful stays the status quo, wrong evaluation counts
/// would be worse.
/// Linear `def; delegation(args read def)` shapes. A plain hoist of the
/// delegation past its prefix would place the call ABOVE a definition
/// it reads — a forward reference (`super(context2, ..)` with `context2
/// = ..` below it). javac's attribution for the whole class then
/// collapses: the undefined identifier cascades into "non-static
/// super" and even bare `Object` resolution failures, poisoning every
/// later diagnostic in the file (weibo AppCompatTextView — the root of
/// a 4.1k-file Object cascade). The original source had the def's
/// expression INLINE in the delegation args; d8 computed it into a
/// register first. Inline the def into the args (the def is read
/// exactly once there — evaluation count preserved even for calls),
/// and when the register is REASSIGNED later (a fresh generation
/// sharing the slot), convert that first write into the declaration so
/// the var stays defined for its later readers. Any shape that cannot
/// be proven aborts untouched.
/// Count WRITE positions of `var` (assign / inc-dec targets) — the
/// shape-C validator needs exact counts, not just presence.
fn stmts_count_writes(stmts: &[Stmt], var: u32) -> usize {
    let mut n = 0usize;
    for s in stmts {
        let mut c = s.clone();
        walk_stmt_exprs(&mut c, &mut |e| {
            deep_rewrite(e, &mut |x| match x {
                Expr::Assign { target, .. }
                    if matches!(&**target, Expr::Local { var: v, .. } if *v == var) =>
                {
                    n += 1;
                }
                Expr::PreIncDec { e, .. } | Expr::PostIncDec { e, .. }
                    if matches!(&**e, Expr::Local { var: v, .. } if *v == var) =>
                {
                    n += 1;
                }
                _ => {}
            });
        });
    }
    n
}

/// Collect every local WRITTEN in `stmts` — the complement inside a
/// ctor prefix is the param set (the only locals a pre-delegation arg
/// expression may read).
fn prefix_written_vars(stmts: &[Stmt]) -> jdc_core::FxHashSet<u32> {
    let mut set = jdc_core::FxHashSet::default();
    for s in stmts {
        let mut c = s.clone();
        walk_stmt_exprs(&mut c, &mut |e| {
            deep_rewrite(e, &mut |x| match x {
                Expr::Assign { target, .. } => {
                    if let Expr::Local { var, .. } = &**target {
                        set.insert(*var);
                    }
                }
                Expr::PreIncDec { e, .. } | Expr::PostIncDec { e, .. } => {
                    if let Expr::Local { var, .. } = &**e {
                        set.insert(*var);
                    }
                }
                _ => {}
            });
        });
        if let Stmt::LocalDef { var, .. } = s {
            set.insert(*var);
        }
    }
    set
}

/// Is `e` safe to evaluate INSIDE a ctor-delegation argument (before
/// this/super exists)? Params/consts/pure ops only — no instance-field
/// reads, no `this`, no captures.
fn pre_this_safe(e: &Expr, prefix_vars: &jdc_core::FxHashSet<u32>) -> bool {
    match e {
        Expr::Local { var, .. } => !prefix_vars.contains(var),
        Expr::Const(_) => true,
        Expr::Cast { e, .. } => pre_this_safe(e, prefix_vars),
        Expr::Bin { l, r, .. } => {
            pre_this_safe(l, prefix_vars) && pre_this_safe(r, prefix_vars)
        }
        Expr::Cond { c, t, f } => {
            pre_this_safe(c, prefix_vars)
                && pre_this_safe(t, prefix_vars)
                && pre_this_safe(f, prefix_vars)
        }
        Expr::Field { owner, is_static, .. } => {
            *is_static
                && owner
                    .as_ref()
                    .is_none_or(|o| pre_this_safe(o, prefix_vars))
        }
        Expr::Method {
            owner,
            args,
            is_static,
            ..
        } => {
            args.iter().all(|a| pre_this_safe(a, prefix_vars))
                && match owner {
                    Some(o) => pre_this_safe(o, prefix_vars),
                    None => *is_static,
                }
        }
        _ => false,
    }
}

/// `s` is exactly one plain assignment to local `v` (optionally wrapped
/// in a singleton Block): the branch shape of a Kotlin default-arg
/// override.
fn single_assign_to_v(s: &Stmt, v: u32) -> Option<Expr> {
    match s {
        Stmt::ExprStmt(Expr::Assign {
            target,
            op: AssignOp::Plain,
            value,
        }) if matches!(&**target, Expr::Local { var: vv, .. } if *vv == v) => {
            Some((**value).clone())
        }
        Stmt::Block(xs) if xs.len() == 1 => single_assign_to_v(&xs[0], v),
        _ => None,
    }
}

/// Kotlin default-argument BRIDGE ctors (shape C of the delegation
/// family): `<init>(params.., int mask, DefaultConstructorMarker)`
/// computes each defaulted arg into a local — `v = p; if ((mask&bit)
/// != 0) { v = DEFAULT; }` — then delegates `this(.., v, ..)`. Java
/// allows NOTHING before the delegation, so the computations must fold
/// INTO the args (`this(.., (mask&bit) != 0 ? DEFAULT : p, ..)`).
/// Unfolded, the hoist passes lift the delegation above the raw local
/// reads: "找不到符号 变量 str2/v4/creationExtras2" — 2.5k root files
/// across weixin/lark/weibo (weixin MvvmObserverOwner$..Observer, lark
/// SimpleArrayMap/LongSparseArray). Per-var provability: exactly one
/// top-level base write, an optional single conditional override whose
/// branches are lone assignments, no other prefix touch of the var,
/// nothing after the delegation touches it, and the folded expression
/// is pre-this-safe. Unprovable vars stay untouched (partial folds are
/// strictly better — the rest was broken before too).
/// Flatten nested plain Blocks among the top-level statements. The
/// structurer hands ctor bodies as region-nested blocks (`Block([def,
/// Block([assign, if]), Block([delegate, return])])` — the Kotlin
/// bridge shape), and every delegation-repair pass scans the TOP level
/// only. Straight-line nesting flattens without semantics; control
/// flow lives inside If/While/etc. arms, never as a direct member.
fn flatten_top_blocks(stmts: &mut Vec<Stmt>) {
    fn rec(s: Stmt, out: &mut Vec<Stmt>) {
        match s {
            Stmt::Block(inner) => {
                for x in inner {
                    rec(x, out);
                }
            }
            other => out.push(other),
        }
    }
    if !stmts.iter().any(|s| matches!(s, Stmt::Block(_))) {
        return;
    }
    let mut out: Vec<Stmt> = Vec::with_capacity(stmts.len());
    for s in std::mem::take(stmts) {
        rec(s, &mut out);
    }
    *stmts = out;
}

fn fold_default_arg_bridge(stmts: &mut Vec<Stmt>) -> bool {
    flatten_top_blocks(stmts);
    let Some(pos) = stmts.iter().position(is_bare_ctor_call) else {
        return false;
    };
    if pos == 0 {
        return false;
    }
    let Stmt::ExprStmt(Expr::Method { args, .. }) = &stmts[pos] else {
        return false;
    };
    let mut arg_vars: Vec<u32> = Vec::new();
    let mut reads = 0usize;
    for a in args {
        let mut c = a.clone();
        deep_rewrite_reads(&mut c, &mut |x| {
            if let Expr::Local { var, .. } = x {
                reads += 1;
                if !arg_vars.contains(var) {
                    arg_vars.push(*var);
                }
            }
        });
    }
    if arg_vars.is_empty() || reads != arg_vars.len() {
        return false; // a var read twice would duplicate evaluation
    }
    // The bridge ENDS at the delegation: nothing after may touch the
    // arg vars (reads OR writes).
    for &v in &arg_vars {
        if stmts_read_var(&stmts[pos + 1..], v) != 0
            || stmts_count_writes(&stmts[pos + 1..], v) != 0
        {
            return false;
        }
    }
    let prefix_vars = prefix_written_vars(&stmts[..pos]);
    let mut repl: Vec<(u32, Expr)> = Vec::new();
    let mut drop: Vec<usize> = Vec::new();
    for &v in &arg_vars {
        // Exact prefix shape for v.
        let mut base: Option<(usize, Expr)> = None;
        let mut decl: Option<usize> = None;
        let mut condf: Option<(usize, Expr, Option<Expr>, Option<Expr>)> = None;
        let mut ok = true;
        for (i, s) in stmts[..pos].iter().enumerate() {
            match s {
                Stmt::LocalDef { var, init, .. } if *var == v => match init {
                    None => {
                        if decl.is_some() {
                            ok = false;
                            break;
                        }
                        decl = Some(i);
                    }
                    Some(e) => {
                        if base.is_some() {
                            ok = false;
                            break;
                        }
                        base = Some((i, e.clone()));
                    }
                },
                Stmt::ExprStmt(Expr::Assign {
                    target,
                    op: AssignOp::Plain,
                    value,
                }) if matches!(&**target, Expr::Local { var: vv, .. } if *vv == v) => {
                    if base.is_some() {
                        ok = false;
                        break;
                    }
                    base = Some((i, (**value).clone()));
                }
                Stmt::If {
                    cond,
                    then_stmt,
                    else_stmt,
                } => {
                    let t = single_assign_to_v(then_stmt, v);
                    let f = else_stmt.as_ref().and_then(|b| single_assign_to_v(b, v));
                    let then_touches = t.is_some()
                        || stmts_read_var(std::slice::from_ref(&**then_stmt), v) != 0
                        || stmts_count_writes(std::slice::from_ref(&**then_stmt), v) != 0;
                    let else_touches = else_stmt.as_ref().is_some_and(|b| {
                        f.is_some()
                            || stmts_read_var(std::slice::from_ref(b), v) != 0
                            || stmts_count_writes(std::slice::from_ref(b), v) != 0
                    });
                    if !then_touches && !else_touches {
                        continue; // unrelated if
                    }
                    // Both branches must be lone assignments (a branch
                    // with its own delegation/return is the conditional-
                    // super machinery's shape, not this one), the cond
                    // must not read v, and only one override per var.
                    if condf.is_some()
                        || base.is_none()
                        || (then_touches && t.is_none())
                        || (else_touches && f.is_none())
                    {
                        ok = false;
                        break;
                    }
                    let cond_stmt = Stmt::ExprStmt(cond.clone());
                    if stmts_read_var(std::slice::from_ref(&cond_stmt), v) != 0 {
                        ok = false;
                        break;
                    }
                    condf = Some((i, cond.clone(), t, f));
                }
                _ => {}
            }
        }
        if !ok {
            continue;
        }
        let Some((bi, be)) = base else { continue };
        // Exact write/read accounting: base (+then/else) writes, zero
        // prefix reads.
        let want_writes = 1
            + condf
                .as_ref()
                .map(|(_, _, t, f)| t.is_some() as usize + f.is_some() as usize)
                .unwrap_or(0);
        if stmts_count_writes(&stmts[..pos], v) != want_writes
            || stmts_read_var(&stmts[..pos], v) != 0
        {
            continue;
        }
        let rep = match condf {
            Some((ci, c, t, f)) => {
                drop.push(ci);
                match (t, f) {
                    (Some(t), Some(f)) => Expr::Cond {
                        c: Box::new(c),
                        t: Box::new(t),
                        f: Box::new(f),
                    },
                    (Some(t), None) => Expr::Cond {
                        c: Box::new(c),
                        t: Box::new(t),
                        f: Box::new(be.clone()),
                    },
                    (None, Some(f)) => Expr::Cond {
                        c: Box::new(c),
                        t: Box::new(be.clone()),
                        f: Box::new(f),
                    },
                    (None, None) => unreachable!("condf requires a branch assign"),
                }
            }
            None => be.clone(),
        };
        if !pre_this_safe(&rep, &prefix_vars) {
            continue;
        }
        drop.push(bi);
        if let Some(d) = decl {
            drop.push(d);
        }
        repl.push((v, rep));
    }
    if repl.is_empty() {
        return false;
    }
    if let Stmt::ExprStmt(Expr::Method { args, .. }) = &mut stmts[pos] {
        for a in args.iter_mut() {
            deep_rewrite_reads(a, &mut |x| {
                if let Expr::Local { var, .. } = x {
                    if let Some((_, e)) = repl.iter().find(|(vv, _)| vv == var) {
                        *x = e.clone();
                    }
                }
            });
        }
    }
    drop.sort_unstable();
    drop.dedup();
    for i in drop.into_iter().rev() {
        stmts.remove(i);
    }
    true
}

/// Rewrite static member references on Kotlin multi-file facade PARTS
/// (`StringsKt__StringsKt.trim(..)`) to the public facade the parts are
/// compiled into (`StringsKt.trim(..)`): the parts are package-private,
/// so every cross-package call site is "在kotlin.text中不是公共的; 无法
/// 从外部程序包中对其进行访问" (lark 1.4k root files; weibo's 8.4k-line
/// Kt cluster). Static members resolve through the facade by
/// inheritance (the map is gated on the extends chain).
pub fn rewrite_kotlin_facades(body: &mut Stmt, pool: &crate::DexPool) {
    let map = pool.kotlin_facade_map();
    if map.is_empty() {
        return;
    }
    walk_stmt_exprs(body, &mut |e| {
        match e {
            Expr::Method {
                cls,
                name,
                desc,
                is_static,
                ..
            } if *is_static => {
                if let Some((base, cover)) = map.get(cls.as_ref()) {
                    let hit = match cover {
                        None => true,
                        Some(c) => c.0.contains(&(name.to_string(), desc.to_string())),
                    };
                    if hit {
                        *cls = std::sync::Arc::from(base.as_str());
                    }
                }
            }
            Expr::Field {
                cls,
                name,
                is_static,
                ..
            } if *is_static => {
                if let Some((base, cover)) = map.get(cls.as_ref()) {
                    let hit = match cover {
                        None => true,
                        Some(c) => c.1.contains(name.as_ref()),
                    };
                    if hit {
                        *cls = std::sync::Arc::from(base.as_str());
                    }
                }
            }
            _ => {}
        }
    });
}

/// Kotlin default-arg bridge fold for ENUM ctors: the synthetic
/// `(String, int, .., int, DefaultConstructorMarker)` ctor computes
/// defaulted args then chains `this(..)` mid-body — Java requires the
/// delegation first (对this的调用必须是构造器中的第一个语句, lark's
/// UserCustomStatusExtraParams$* family, 752 lines). Same fold the
/// class-ctor path runs; the enum branch of the pipeline used to skip
/// it (only strip_enum_ctor_super ran there).
pub fn fold_enum_default_arg_bridge(body: &mut Stmt) {
    let Stmt::Block(stmts) = body else { return };
    fold_default_arg_bridge(stmts);
}

pub fn fix_ctor_delegation_arg_defs(body: &mut Stmt) {
    let Stmt::Block(stmts) = body else { return };
    // Shape C first: the Kotlin default-arg bridge (computations +
    // conditional overrides folded into the delegation args).
    fold_default_arg_bridge(stmts);
    // Only the top-level linear shape; the first statement needs no
    // repair and control flow ahead of the delegation belongs to the
    // conditional-super machinery.
    let Some(pos) = stmts.iter().position(is_bare_ctor_call) else {
        return;
    };
    if pos == 0 {
        return;
    }
    // Vars read by the delegation args, and the total read count (a var
    // read twice would duplicate a call evaluation on inline).
    let mut arg_vars: Vec<u32> = Vec::new();
    let mut total_reads = 0usize;
    {
        let Stmt::ExprStmt(Expr::Method { args, .. }) = &stmts[pos] else {
            return;
        };
        for a in args {
            let mut c = a.clone();
            deep_rewrite_reads(&mut c, &mut |x| {
                if let Expr::Local { var: v, .. } = x {
                    total_reads += 1;
                    if !arg_vars.contains(v) {
                        arg_vars.push(*v);
                    }
                }
            });
        }
    }
    if arg_vars.is_empty() || total_reads != arg_vars.len() {
        return;
    }
    // Vars DEFINED anywhere in the prefix (for the init-referenced
    // check below — an inlined init may not itself read prefix defs).
    let prefix_defs: Vec<u32> = stmts[..pos]
        .iter()
        .filter_map(|s| match s {
            Stmt::LocalDef { var, init: Some(_), .. } => Some(*var),
            _ => None,
        })
        .collect();
    // Per referenced var: exactly one prefix def, no other prefix
    // reader between def and delegation, the def's init reads no
    // prefix-def var, and the first post-delegation use is a top-level
    // write (becomes the declaration) or nothing at all.
    let mut plan: Vec<(u32, usize, Option<usize>)> = Vec::new();
    for v in arg_vars {
        let defs: Vec<usize> = stmts[..pos]
            .iter()
            .enumerate()
            .filter(|(i, _)| {
                matches!(&stmts[*i], Stmt::LocalDef { var, init: Some(_), .. } if *var == v)
            })
            .map(|(i, _)| i)
            .collect();
        if defs.len() > 1 {
            return; // ambiguous: multiple prefix defs
        }
        let Some(&q) = defs.first() else {
            continue; // a param: nothing to inline for this var
        };
        let init = match &stmts[q] {
            Stmt::LocalDef { init: Some(e), .. } => e.clone(),
            _ => return,
        };
        if stmts_read_var(&stmts[q + 1..pos], v) != 0 {
            return; // another reader between the def and the delegation
        }
        // The inlined init may not read a prefix-def var either — the
        // delegation lands ABOVE those defs after the hoist.
        let mut init_vars: Vec<u32> = Vec::new();
        deep_rewrite_reads(&mut { init.clone() }, &mut |x| {
            if let Expr::Local { var: vv, .. } = x {
                if !init_vars.contains(vv) {
                    init_vars.push(*vv);
                }
            }
        });
        if init_vars.iter().any(|iv| prefix_defs.contains(iv)) {
            return;
        }
        match stmts[pos + 1..]
            .iter()
            .position(|s| {
                matches!(s, Stmt::ExprStmt(Expr::Assign { target, .. })
                    if matches!(&**target, Expr::Local { var: vv, .. } if *vv == v))
            }) {
            Some(w) => {
                // Reads before the re-declaration would be dangling.
                if stmts_read_var(&stmts[pos + 1..pos + 1 + w], v) != 0 {
                    return;
                }
                plan.push((v, q, Some(pos + 1 + w)));
            }
            None => {
                // No later write: the def must be dead after inline.
                if stmts_read_var(&stmts[pos + 1..], v) != 0 {
                    return;
                }
                plan.push((v, q, None));
            }
        }
    }
    if plan.is_empty() {
        return;
    }
    // Inline the def inits into the delegation args.
    let values: Vec<(u32, Expr)> = plan
        .iter()
        .map(|(_v, q, _)| match &stmts[*q] {
            Stmt::LocalDef { var, init: Some(e), .. } => (*var, e.clone()),
            _ => unreachable!("plan entries carry a LocalDef with init"),
        })
        .collect();
    if let Stmt::ExprStmt(Expr::Method { args, .. }) = &mut stmts[pos] {
        for a in args {
            deep_rewrite_reads(a, &mut |x| {
                if let Expr::Local { var: v, .. } = x {
                    if let Some((_, e)) = values.iter().find(|(vv, _)| vv == v) {
                        *x = e.clone();
                    }
                }
            });
        }
    }
    // Convert the first writes into declarations BEFORE removing defs
    // (removals shift indices); then remove the defs in descending
    // order.
    for (v, _, w) in &plan {
        if let Some(w) = w {
            if let Stmt::ExprStmt(Expr::Assign { target, value, .. }) = &mut stmts[*w] {
                if matches!(&**target, Expr::Local { var: vv, .. } if vv == v) {
                    let taken = std::mem::replace(&mut **value, Expr::Const(ConstVal::Null));
                    stmts[*w] = Stmt::LocalDef {
                        var: *v,
                        init: Some(taken),
                        is_final: false,
                        force_type: false,
                    };
                }
            }
        }
    }
    let mut order: Vec<usize> = plan.iter().map(|(_, q, _)| *q).collect();
    order.sort_unstable();
    order.reverse();
    for q in order {
        stmts.remove(q);
    }
}

/// An INT-typed method returning a boolean value: the register held the
/// boolean test result in one generation and the `if (v) 1 else 0` int
/// in another; booleanize picks the boolean generation and the plain
/// `return v;` breaks ("boolean无法转换为int", weixin Handle
/// onPausableTransaction — the source was `if (v) 1 else 0`). Wrap the
/// return in the recovering conditional.
/// Mirror of fix_int_returns: a BOOLEAN method returning a numeric-
/// typed value (register reuse left an int generation) wraps it
/// `x != 0` — the dex branch encoding, and the only legal Java form
/// (kh5/a `return v116_g53;` int无法转换为boolean family).
pub fn fix_bool_returns(vt: &VarTable, body: &mut Stmt) {
    walk_mut_deep(body, &mut |st| {
        if let Stmt::Return(Some(e)) = st {
            let numeric = match &*e {
                Expr::Local { var, ty } => {
                    let t = if (*var as usize) < vt.vars.len() {
                        vt.var(*var).ty.erased()
                    } else {
                        ty.erased()
                    };
                    matches!(
                        t,
                        JavaType::Int
                            | JavaType::Long
                            | JavaType::Short
                            | JavaType::Byte
                            | JavaType::Char
                    )
                }
                other => matches!(
                    other.type_ref().erased(),
                    JavaType::Int | JavaType::Long | JavaType::Short | JavaType::Byte
                        | JavaType::Char
                ),
            };
            if numeric {
                let taken = e.clone();
                *e = Expr::Bin {
                    op: BinOp::Ne,
                    l: Box::new(taken),
                    r: Box::new(Expr::Const(ConstVal::Int(0))),
                    ty: Some(TypeRef::J(JavaType::Boolean)),
                };
            }
        }
    });
}

pub fn fix_int_returns(vt: &VarTable, body: &mut Stmt) {
    walk_mut_deep(body, &mut |st| {
        if let Stmt::Return(Some(e)) = st {
            let is_bool = match e {
                Expr::Local { var, .. } => {
                    (*var as usize) < vt.vars.len()
                        && vt.vars[*var as usize].ty.erased() == JavaType::Boolean
                }
                Expr::Method { desc, .. } => desc.ret == JavaType::Boolean,
                _ => false,
            };
            if is_bool {
                *e = Expr::Cond {
                    c: Box::new(e.clone()),
                    t: Box::new(Expr::Const(ConstVal::Int(1))),
                    f: Box::new(Expr::Const(ConstVal::Int(0))),
                };
            }
        }
    });
}

/// Generation splitting: when an assignment's value type is
/// INCOMPATIBLE with the var's declared type, mint a FRESH var for the
/// new generation instead of widening (widening was measured twice as
/// net-negative — every use-site cast gap re-triggers javac's
/// error-type contagion). Reads after the split point follow the
/// active generation; control-flow joins intersect; loops run a
/// 3-round fixpoint so the back-edge carries the tail generation to
/// the head reads (the loop-state-tuple shape, qf5/v0's
/// `u0 = (qf5.u0) get;` … `u0 = looper2;`).
///
/// Split condition (reference incompatibility or a primitive/value
/// mix — the instanceof-corruption shape): both specific references of
/// different classes, or prim→ref. NOT numeric-vs-numeric (promotion
/// handles those) and NOT Object targets (assignable — the narrowing
/// cast pass covers the value side).
pub fn split_generations(vt: &mut VarTable, body: &mut Stmt) {
    let mut counter: u32 = 0;
    let mut gen: std::collections::HashMap<u32, u32> = std::collections::HashMap::default();
    split_walk_stmt(body, vt, &mut gen, &mut counter);
}

/// Should the assignment `target = value` split the target?
fn split_needed(vt: &VarTable, target: u32, value: &Expr) -> bool {
    let n = vt.vars.len();
    if target as usize >= n {
        return false;
    }
    let declared = vt.vars[target as usize].ty.erased();
    let vt_is_ref = |t: &JavaType| matches!(t, JavaType::Object(_) | JavaType::Array(_));
    // Locals consult the VarTable: the embedded ty is a lift-time
    // snapshot, stale after booleanize converts a copy SOURCE (the
    // post-booleanize re-split below relies on seeing `v131` as the
    // boolean it became). Bitwise Or/And/Xor over boolean operands
    // carry the same staleness at the EXPRESSION level (dex lowered
    // Kotlin's non-short-circuit `or` to int `|` — the embedded Bin ty
    // stays Int after booleanize converts the operands): `int v18 =
    // delete | delete2` must split the target generation.
    fn side_bool(e: &Expr, vt: &VarTable) -> bool {
        match e {
            Expr::Local { var, .. } if (*var as usize) < vt.vars.len() => {
                matches!(vt.var(*var).ty.erased(), JavaType::Boolean)
            }
            Expr::Const(ConstVal::Int(0 | 1)) => true,
            Expr::Bin { op: BinOp::Or | BinOp::And | BinOp::Xor, l, r, .. } => {
                side_bool(l, vt) && side_bool(r, vt)
            }
            other => matches!(other.type_ref().erased(), JavaType::Boolean),
        }
    }
    let value_ty = match value {
        Expr::Local { var, ty } if (*var as usize) < vt.vars.len() => vt.var(*var).ty.erased(),
        Expr::Bin {
            op: BinOp::Or | BinOp::And | BinOp::Xor,
            l,
            r,
            ..
        } if side_bool(l, vt) && side_bool(r, vt) => JavaType::Boolean,
        other => other.type_ref().erased(),
    };
    if vt_is_ref(&declared) && vt_is_ref(&value_ty) {
        // Both references: split only when incompatible — different
        // classes where neither side is Object.
        let obj = JavaType::Object("java/lang/Object".into());
        declared != value_ty && declared != obj && value_ty != obj
    } else {
        // Primitive/reference mix: the value generation has a kind the
        // target can never accept — split (the declared type stays with
        // the old generation's readers).
        if vt_is_ref(&declared) != vt_is_ref(&value_ty) {
            return true;
        }
        // Boolean/numeric mix: `boolean` and `int` have NO cast between
        // them in Java, so a register reused across the kinds can only
        // be expressed as two generations (weixin ConstraintLayout
        // `boolean v60; int v56; v60 = v56;` — 9.5k bool↔int lines once
        // the obscuring suppression lifted). 0/1 constants are the
        // boolean encoding, not a numeric generation — never split on
        // those (booleanize owns them).
        let d_bool = matches!(declared, JavaType::Boolean);
        let v_bool = matches!(value_ty, JavaType::Boolean);
        let zero_one = matches!(value, Expr::Const(ConstVal::Int(0 | 1)));
        d_bool != v_bool && !zero_one
    }
}

fn rewrite_gen_reads(e: &mut Expr, gen: &std::collections::HashMap<u32, u32>, vt: &VarTable) {
    deep_rewrite(e, &mut |x| {
        if let Expr::Local { var, ty } = x {
            if let Some(&to) = gen.get(var) {
                if to != *var {
                    *var = to;
                    *ty = vt.var(to).ty.clone();
                }
            }
        }
    });
}

fn do_split(
    vt: &mut VarTable,
    target: &mut Expr,
    old: u32,
    value_ty: &JavaType,
    gen: &mut std::collections::HashMap<u32, u32>,
    counter: &mut u32,
) {
    *counter += 1;
    let info = &vt.vars[old as usize];
    let id = vt.vars.len() as u32;
    let name = format!("{}_g{}", info.name, counter);
    let slot = info.slot;
    // A split generation is a fresh LOCAL, not a parameter — even when
    // the parent register is one (the param identity stays on the
    // original var id; the generation only carries a later write). The
    // inherited flag made booleanize (and every other param-skip pass)
    // permanently ignore param-register generations: weixin v2/i's
    // `int v264_g160_g7 = !v200` with `!= 0` reads (bool→int assign
    // family, 2.8k lines).
    let is_param = false;
    vt.vars.push(jdc_core::var::VarInfo {
        id,
        slot,
        name,
        ty: TypeRef::J(value_ty.clone()),
        is_param,
        range_start: 0,
        range_end: u16::MAX,
        synthetic_name: true,
    });
    while vt.by_slot.len() <= slot as usize {
        vt.by_slot.push(Vec::new());
    }
    vt.by_slot[slot as usize].push((0, u16::MAX, id));
    gen.insert(old, id);
    if let Expr::Local { var, ty, .. } = target {
        *var = id;
        *ty = TypeRef::J(value_ty.clone());
    }
}

fn split_walk_stmt(
    st: &mut Stmt,
    vt: &mut VarTable,
    gen: &mut std::collections::HashMap<u32, u32>,
    counter: &mut u32,
) {
    match st {
        Stmt::Block(v) => {
            for x in v.iter_mut() {
                split_walk_stmt(x, vt, gen, counter);
            }
        }
        Stmt::ExprStmt(e) => {
            rewrite_gen_reads(e, gen, vt);
            if let Expr::Assign {
                target,
                value,
                op: AssignOp::Plain,
                ..
            } = e
            {
                if let Expr::Local { var, .. } = &**target {
                    let old = *var;
                    if split_needed(vt, old, value) {
                        let value_ty = value.type_ref().erased();
                        do_split(vt, target, old, &value_ty, gen, counter);
                    }
                }
            }
        }
        Stmt::LocalDef { var, init, .. } => {
            if let Some(e) = init {
                rewrite_gen_reads(e, gen, vt);
                if split_needed(vt, *var, e) {
                    // The DEF mints its own generation: retarget the def
                    // to a fresh var (the bare decl of the ORIGINAL stays
                    // for its earlier readers).
                    let value_ty = e.type_ref().erased();
                    let old = *var;
                    let mut fake = Expr::Local {
                        var: old,
                        ty: vt.vars[old as usize].ty.clone(),
                    };
                    do_split(vt, &mut fake, old, &value_ty, gen, counter);
                    if let Expr::Local { var: nv, .. } = fake {
                        *var = nv;
                    }
                }
            }
        }
        Stmt::If {
            cond,
            then_stmt,
            else_stmt,
            ..
        } => {
            rewrite_gen_reads(cond, gen, vt);
            let mut g_then = gen.clone();
            split_walk_stmt(then_stmt, vt, &mut g_then, counter);
            let mut g_else = gen.clone();
            if let Some(e) = else_stmt {
                split_walk_stmt(e, vt, &mut g_else, counter);
            }
            // Join: keep only splits BOTH paths produced (an absent else
            // is a fall-through path that keeps the pre-if generation).
            gen.retain(|k, v| g_then.get(k) == Some(v) && g_else.get(k) == Some(v));
        }
        Stmt::While { cond, body, .. } | Stmt::DoWhile { cond, body, .. } => {
            // 3-round fixpoint: round N walks the cond+body with the
            // accumulated gen — the back-edge carries the tail
            // generation into the head reads of the next round.
            let entry = gen.clone();
            for _ in 0..3 {
                rewrite_gen_reads(cond, gen, vt);
                split_walk_stmt(body, vt, gen, counter);
            }
            // After the loop the pre-loop generation is what a
            // zero-iteration execution left — conservative.
            *gen = entry;
        }
        Stmt::For { init, body, .. } => {
            for x in init.iter_mut() {
                split_walk_stmt(x, vt, gen, counter);
            }
            let entry = gen.clone();
            for _ in 0..3 {
                split_walk_stmt(body, vt, gen, counter);
            }
            *gen = entry;
        }
        Stmt::ForEach { body, .. } => {
            let entry = gen.clone();
            for _ in 0..3 {
                split_walk_stmt(body, vt, gen, counter);
            }
            *gen = entry;
        }
        Stmt::Switch { cases, default, .. } => {
            let entry = gen.clone();
            for c in cases.iter_mut() {
                let mut g_case = entry.clone();
                for x in c.body.iter_mut() {
                    split_walk_stmt(x, vt, &mut g_case, counter);
                }
                gen.retain(|k, v| g_case.get(k) == Some(v));
            }
            if let Some(d) = default {
                let mut g_def = entry.clone();
                split_walk_stmt(d, vt, &mut g_def, counter);
                gen.retain(|k, v| g_def.get(k) == Some(v));
            }
        }
        Stmt::Try {
            body,
            catches,
            finally,
        } => {
            let entry = gen.clone();
            let mut g_try = entry.clone();
            split_walk_stmt(body, vt, &mut g_try, counter);
            let mut g_all = g_try.clone();
            for c in catches.iter_mut() {
                // The handler runs with the PRE-try state (the exception
                // may fire anywhere in the try).
                let mut g_c = entry.clone();
                split_walk_stmt(&mut c.body, vt, &mut g_c, counter);
                g_all.retain(|k, v| g_c.get(k) == Some(v));
            }
            *gen = g_all;
            if let Some(f) = finally {
                split_walk_stmt(f, vt, gen, counter);
            }
        }
        Stmt::Synchronized { body, .. } | Stmt::Labeled { body, .. } => {
            split_walk_stmt(body, vt, gen, counter);
        }
        Stmt::Return(Some(e)) | Stmt::Throw(e) => {
            rewrite_gen_reads(e, gen, vt);
        }
        _ => {}
    }
}

/// Dangling `break L<id>`: a Goto whose paired Label/Labeled-wrap was
/// lost to structure degradation prints `break L<id>;` against an
/// undeclared label ("未定义的标签", weibo 371/lark 85/weixin 535).
/// Inside a loop the goto-to-loop-exit shape degrades to a plain
/// `break` — compilable, and the dominant original semantic. A Goto
/// whose Label DOES exist in the method stays (the pair is valid);
/// a Goto outside any loop stays as-is (no honest source form).
pub fn resolve_dangling_gotos(s: &mut Stmt) {
    let mut labels: jdc_core::FxHashSet<u32> = jdc_core::FxHashSet::default();
    let probe = s.clone();
    walk_all(&probe, &mut |st| {
        if let Stmt::Label(id) = st {
            labels.insert(*id);
        }
    });
    resolve_gotos_walk(s, &labels, 0);
}

fn resolve_gotos_walk(s: &mut Stmt, labels: &jdc_core::FxHashSet<u32>, loop_depth: u32) {
    let depth = match s {
        Stmt::While { .. } | Stmt::DoWhile { .. } | Stmt::For { .. } | Stmt::ForEach { .. } => {
            loop_depth + 1
        }
        _ => loop_depth,
    };
    match s {
        Stmt::Goto(id) => {
            if !labels.contains(id) && depth > 0 {
                *s = Stmt::Break(None);
            }
        }
        Stmt::Block(v) => {
            for x in v.iter_mut() {
                resolve_gotos_walk(x, labels, depth);
            }
        }
        Stmt::If { then_stmt, else_stmt, .. } => {
            resolve_gotos_walk(then_stmt, labels, depth);
            if let Some(e) = else_stmt {
                resolve_gotos_walk(e, labels, depth);
            }
        }
        Stmt::While { body, .. }
        | Stmt::DoWhile { body, .. }
        | Stmt::For { body, .. }
        | Stmt::ForEach { body, .. }
        | Stmt::Labeled { body, .. }
        | Stmt::Synchronized { body, .. } => resolve_gotos_walk(body, labels, depth),
        Stmt::Try {
            body,
            catches,
            finally,
        } => {
            resolve_gotos_walk(body, labels, depth);
            for c in catches.iter_mut() {
                resolve_gotos_walk(&mut c.body, labels, depth);
            }
            if let Some(f) = finally {
                resolve_gotos_walk(f, labels, depth);
            }
        }
        Stmt::Switch { cases, default, .. } => {
            for c in cases.iter_mut() {
                for x in c.body.iter_mut() {
                    resolve_gotos_walk(x, labels, depth);
                }
            }
            if let Some(d) = default {
                resolve_gotos_walk(d, labels, depth);
            }
        }
        _ => {}
    }
}

/// READS of `v` across the statements (assignment targets excluded).
fn stmts_read_var(stmts: &[Stmt], v: u32) -> usize {
    let mut n = 0usize;
    for s in stmts {
        let mut c = s.clone();
        walk_stmt_exprs(&mut c, &mut |e| {
            deep_rewrite_reads(e, &mut |x| {
                if let Expr::Local { var: vv, .. } = x {
                    if *vv == v {
                        n += 1;
                    }
                }
            });
        });
    }
    n
}

pub fn fix_ctor_conditional_super(body: &mut Stmt) {
    // A single-statement body can arrive UNWRAPPED (bare `If` — the
    // gb6/e throw-guard family); the shape scans need a statement list.
    if !matches!(body, Stmt::Block(_)) {
        let inner = std::mem::replace(body, Stmt::Block(Vec::new()));
        *body = Stmt::Block(vec![inner]);
    }
    let Stmt::Block(stmts) = body else { return };
    // Unwrap single-statement Block wrappers: the structurer can nest
    // the whole body one level deeper, hiding the top-level If from the
    // shape scans (cleanup would flatten it — but runs AFTER this pass).
    while stmts.len() == 1 {
        let Stmt::Block(inner) = &stmts[0] else { break };
        *stmts = inner.clone();
    }
    if stmts.is_empty() {
        return;
    }
    if is_bare_ctor_call(stmts.first().unwrap()) {
        dedupe_ctor_delegations(body);
        return;
    }
    if try_linear_super_inline(stmts) {
        return;
    }
    try_merge_branched_super(stmts);
}

/// Shape C: the delegation is already first — strip duplicate copies
/// left by R8 path-duplication (Kotlin default-arg bridge ctors: ft5/j
/// had `super()` leading PLUS another inside a branch — "对super的调用
/// 必须是构造器中的第一个语句" at the copy). Every path delegates
/// through the leading call, so structurally-identical (or empty-args,
/// same-kind) copies nested in blocks/ifs are removed, never moved.
/// Runs both ahead of the shape-A/B attempt and AFTER the plain hoist
/// (fix_ctor_super_first) — the hoist is what puts the leading
/// delegation in place for path-duplicated ctors.
pub fn dedupe_ctor_delegations(body: &mut Stmt) {
    let Stmt::Block(stmts) = body else { return };
    let Some(d0) = stmts.first().and_then(|s| match s {
        Stmt::ExprStmt(e) if is_delegation_expr(e) => Some(e.clone()),
        _ => None,
    }) else {
        return;
    };
    fn rec(s: &mut Stmt, d0: &Expr) {
        match s {
            Stmt::Block(v) => {
                v.retain(|x| {
                    !matches!(x, Stmt::ExprStmt(e) if is_delegation_expr(e) && same_delegation(e, d0))
                });
                for x in v.iter_mut() {
                    rec(x, d0);
                }
            }
            Stmt::If { then_stmt, else_stmt, .. } => {
                rec(then_stmt, d0);
                if let Some(e) = else_stmt {
                    rec(e, d0);
                }
            }
            _ => {}
        }
    }
    // Top-level copies first (rec only strips copies NESTED in
    // blocks/ifs — a duplicate `super()` sitting directly in the body
    // list fell through its `_` arm: weixin ft5/j's second super()).
    {
        let d0r = &d0;
        let mut idx = 0usize;
        stmts.retain(|s| {
            idx += 1;
            idx == 1
                || !(matches!(s, Stmt::ExprStmt(e)
                    if is_delegation_expr(e) && same_delegation(e, d0r)))
        });
    }
    for s in stmts.iter_mut().skip(1) {
        rec(s, &d0);
    }
}

/// Structural delegation identity for dedup: same kind/target and equal
/// args — or both arg-less (`super()` copies across duplicated paths
/// render with locally-renamed args yet delegate identically).
fn same_delegation(a: &Expr, b: &Expr) -> bool {
    match (a, b) {
        (
            Expr::Method { name: n1, cls: c1, is_super: s1, args: a1, .. },
            Expr::Method { name: n2, cls: c2, is_super: s2, args: a2, .. },
        ) => {
            &**n1 == "<init>"
                && &**n2 == "<init>"
                && c1 == c2
                && s1 == s2
                && (a1 == a2 || (a1.is_empty() && a2.is_empty()))
        }
        _ => false,
    }
}

/// The `Method` expr of a bare ctor-delegation statement.
fn ctor_call_expr(s: &Stmt) -> Option<&Expr> {
    match s {
        Stmt::ExprStmt(e) if is_delegation_expr(e) => Some(e),
        _ => None,
    }
}

/// Same delegation kind ignoring args (super vs this, same target).
fn same_ctor_kind(a: &Expr, b: &Expr) -> bool {
    match (a, b) {
        (
            Expr::Method { cls: c1, is_super: s1, owner: o1, .. },
            Expr::Method { cls: c2, is_super: s2, owner: o2, .. },
        ) => c1 == c2 && s1 == s2 && o1 == o2,
        _ => false,
    }
}

/// Statements of a branch body, recursively flattening pure Blocks —
/// the fix runs BEFORE cleanup, so structurer-emitted nesting is still
/// in place. Any non-Block statement (If/Try/...) stays an item and
/// fails the def/call classification, which is the intended abort.
fn flat_list(s: &Stmt) -> Vec<&Stmt> {
    fn rec<'a>(s: &'a Stmt, out: &mut Vec<&'a Stmt>) {
        match s {
            Stmt::Block(v) => {
                for x in v {
                    rec(x, out);
                }
            }
            other => out.push(other),
        }
    }
    let mut out = Vec::new();
    rec(s, &mut out);
    out
}

/// Blank the OWNER of un-folded `<init>` calls (lost allocation): the
/// printer renders them as `new X(..)` and never reads the owner, so its
/// register reference is not a real use (v7.a$a2: the dead
/// `new f(0,..)`'s owner was v1's register, inflating v1's use count
/// and blocking the inline-hoist).
fn strip_lost_alloc_owners(e: &mut Expr) {
    deep_rewrite(e, &mut |x| {
        if let Expr::Method { name, is_special: true, owner: Some(o), .. } = x {
            if &**name == "<init>" && !matches!(**o, Expr::This) {
                **o = Expr::Const(jdc_core::ir::expr::ConstVal::Int(0));
            }
        }
    });
}

/// Per-var `Local` occurrence counts over an expression (single pass;
/// lost-alloc `<init>` owners excluded — see strip_lost_alloc_owners).
fn count_locals_expr(e: &Expr) -> std::collections::HashMap<u32, usize> {
    let mut m = std::collections::HashMap::new();
    let mut probe = e.clone();
    strip_lost_alloc_owners(&mut probe);
    deep_rewrite(&mut probe, &mut |x| {
        if let Expr::Local { var: v, .. } = x {
            *m.entry(*v).or_insert(0) += 1;
        }
    });
    m
}

pub(crate) fn count_locals_stmts(ss: &[Stmt]) -> std::collections::HashMap<u32, usize> {
    let mut m = std::collections::HashMap::new();
    for s in ss {
        let mut c = s.clone();
        walk_stmt_exprs(&mut c, &mut |e| {
            strip_lost_alloc_owners(e);
            deep_rewrite(e, &mut |x| {
                if let Expr::Local { var: v, .. } = x {
                    *m.entry(*v).or_insert(0) += 1;
                }
            });
        });
    }
    m
}

fn cnt(m: &std::collections::HashMap<u32, usize>, v: u32) -> usize {
    m.get(&v).copied().unwrap_or(0)
}

/// Substitute map-referenced locals, recursively expanding def chains
/// (depth-capped). Returns None when a referenced var has no def or the
/// chain is too deep.
fn inline_locals(
    e: &Expr,
    map: &std::collections::HashMap<u32, Expr>,
    depth: u32,
) -> Option<Expr> {
    if depth > 4 {
        return None;
    }
    let mut out = e.clone();
    let mut fail = false;
    deep_rewrite(&mut out, &mut |x| {
        if let Expr::Local { var, .. } = x {
            if let Some(def) = map.get(var) {
                match inline_locals(def, map, depth + 1) {
                    Some(r) => *x = r,
                    None => fail = true,
                }
            }
        }
    });
    if fail {
        None
    } else {
        Some(out)
    }
}

/// A leading statement that defines a local: (var, init expr).
fn def_of(s: &Stmt) -> Option<(u32, &Expr)> {
    match s {
        Stmt::LocalDef { var, init: Some(e), .. } => Some((*var, e)),
        Stmt::ExprStmt(Expr::Assign {
            target,
            value,
            op: jdc_core::ir::expr::AssignOp::Plain,
            ..
        }) => match &**target {
            Expr::Local { var, .. } => Some((*var, value)),
            _ => None,
        },
        _ => None,
    }
}

/// Shape A: straight-line prefix, delegation references prefix locals.
fn try_linear_super_inline(stmts: &mut Vec<Stmt>) -> bool {
    let Some(pos) = stmts.iter().position(is_bare_ctor_call) else {
        return false;
    };
    if pos == 0 {
        return false; // already first — nothing to do
    }
    // The prefix must be straight-line.
    if !stmts[..pos]
        .iter()
        .all(|s| matches!(s, Stmt::LocalDef { .. } | Stmt::ExprStmt(_)))
    {
        return false;
    }
    let Some(call) = ctor_call_expr(&stmts[pos]) else {
        return false;
    };
    let Expr::Method { args, .. } = call else {
        return false;
    };
    // Defs reachable from the args (last definition wins, bytecode order).
    let mut map: std::collections::HashMap<u32, Expr> =
        std::collections::HashMap::new();
    let mut def_idx: std::collections::HashMap<u32, usize> =
        std::collections::HashMap::new();
    for (i, s) in stmts[..pos].iter().enumerate() {
        if let Some((v, e)) = def_of(s) {
            map.insert(v, e.clone());
            def_idx.insert(v, i);
        }
    }
    // Which arg locals need inlining?
    let mut needed: Vec<u32> = Vec::new();
    for a in args {
        let mut probe = a.clone();
        strip_lost_alloc_owners(&mut probe);
        deep_rewrite(&mut probe, &mut |x| {
            if let Expr::Local { var, .. } = x {
                if map.contains_key(var) && !needed.contains(var) {
                    needed.push(*var);
                }
            }
        });
    }
    if needed.is_empty() {
        return false; // plain hoist handles it
    }
    // Guard: side-effecting defs inline only at a provably preserved
    // call count (exactly one use, the arg site).
    let mut consumed: Vec<usize> = Vec::new();
    let use_counts = count_locals_stmts(stmts);
    for &v in &needed {
        let def = &map[&v];
        let uses = cnt(&use_counts, v);
        if jdc_core::ir::build::has_side_effects(def) && uses != 1 {
            return false;
        }
        if uses == 1 {
            consumed.push(def_idx[&v]);
        }
    }
    // Build the inlined args.
    let mut new_args: Vec<Expr> = Vec::with_capacity(args.len());
    for a in args {
        match inline_locals(a, &map, 0) {
            Some(r) => new_args.push(r),
            None => return false,
        }
    }
    // Rebuild: super first (with inlined args), the unconsumed prefix
    // statements keep their order after it, then the original rest.
    let mut call_stmt = stmts.remove(pos);
    if let Stmt::ExprStmt(Expr::Method { args: slot, .. }) = &mut call_stmt {
        *slot = new_args;
    }
    let mut rest: Vec<Stmt> = Vec::with_capacity(stmts.len() + 1);
    rest.push(call_stmt);
    for (i, s) in stmts.drain(..).enumerate() {
        // Indices shift after `remove(pos)`: consumed holds pre-removal
        // indices; pos itself is already gone from `stmts`.
        let orig = if i >= pos { i + 1 } else { i };
        if !consumed.contains(&orig) {
            rest.push(s);
        }
    }
    *stmts = rest;
    true
}

/// Shape B: if/else branches each ending in the same-kind delegation.
fn try_merge_branched_super(stmts: &mut Vec<Stmt>) -> bool {
    // Candidate If positions — the prelude before the chosen If must be
    // straight-line; try each If until one merges (nested/multi-if
    // ctors exist but the first matching one is the delegation site).
    let if_positions: Vec<usize> = stmts
        .iter()
        .enumerate()
        .filter(|(_, s)| matches!(s, Stmt::If { .. }))
        .map(|(i, _)| i)
        .collect();
    for if_pos in if_positions {
        // Cheap allocation-free gate: at least one branch must hold a
        // delegation (most ctor ifs are field null-checks and must not
        // pay the merge machinery). The OTHER side may be delegation-free
        // (throw-guard shape D) or absent (then-only shape E — the
        // rendered if/else form often only exists after later passes).
        let gate = match &stmts[if_pos] {
            Stmt::If { then_stmt, else_stmt, .. } => {
                contains_delegation(then_stmt)
                    || else_stmt.as_ref().is_some_and(|e| contains_delegation(e))
            }
            _ => false,
        };
        if gate && merge_at(stmts, if_pos) {
            return true;
        }
    }
    false
}

/// Does this subtree contain a ctor delegation? (module-level: shared by
/// the merge gate and split_branch)
fn contains_delegation(s: &Stmt) -> bool {
    match s {
        Stmt::ExprStmt(e) => is_delegation_expr(e),
        Stmt::Block(v) => v.iter().any(contains_delegation),
        Stmt::If { then_stmt, else_stmt, .. } => {
            contains_delegation(then_stmt)
                || else_stmt.as_ref().is_some_and(|e| contains_delegation(e))
        }
        _ => false,
    }
}



/// One merge attempt at `stmts[if_pos]`. See fix_ctor_conditional_super
/// for the doctrine. Extensions over the pure two-call merge:
/// - branch pre-call SIDE-EFFECT statements (Kotlin `o.h(param,..)`
///   null-checks — the zz5/j0 family) are allowed; they move into the
///   branch remainder (after super — the same reordering doctrine the
///   plain hoist already applies; Java has no pre-super statement form).
/// - a branch WITHOUT a delegation (throw-guard: `if (x==null) throw
///   .. else { super(..); .. }` — the gb6/e family) merges as pure
///   remainder; exactly one branch carries the call then, and no
///   ternary args arise (the guard throws before any path needs them).
/// - prelude single-assignment if/else (`if (c) {v=e1} else {v=e2}`)
///   folds into a Cond def for inlining (the zz5/j0 v15/v16 preludes).
fn merge_at(stmts: &mut Vec<Stmt>, if_pos: usize) -> bool {
    /// Branch classification: Call(at, defs, pre-call extra idxs) when a
    /// delegation sits behind only defs/side-effect statements; Clean
    /// when the branch has no delegation at all (pure remainder); Dirty
    /// otherwise (nested/conditional delegation — out of scope).
    enum Br {
        /// (call index, pre-call defs, def statement indices)
        Call(usize, Vec<(u32, Expr)>, Vec<usize>),
        Clean,
        Dirty,
    }
    fn split_branch(list: &[&Stmt]) -> Br {
        let call_pos = list.iter().position(|s| ctor_call_expr(s).is_some());
        let Some(c) = call_pos else {
            // No delegation at this level: a pure remainder branch
            // (throw-guard) unless one hides in nested control flow.
            return if list.iter().any(|s| contains_delegation(s)) {
                Br::Dirty
            } else {
                Br::Clean
            };
        };
        if list.iter().skip(c + 1).any(|s| ctor_call_expr(s).is_some()) {
            return Br::Dirty; // two delegations in one branch
        }
        let mut defs: Vec<(u32, Expr)> = Vec::new();
        let mut def_idxs: Vec<usize> = Vec::new();
        for (i, s) in list.iter().enumerate().take(c) {
            match def_of(s) {
                Some((v, e)) => {
                    defs.push((v, e.clone()));
                    def_idxs.push(i);
                }
                None => match s {
                    // Side-effect statements and bare decls ahead of the
                    // delegation ride along into the remainder.
                    Stmt::ExprStmt(_) | Stmt::LocalDef { .. } => {}
                    _ => return Br::Dirty, // control flow pre-call
                },
            }
        }
        Br::Call(c, defs, def_idxs)
    }
    /// Prelude single-assignment if/else → `v = c ? e1 : e2` def.
    fn cond_def_of(s: &Stmt) -> Option<(u32, Expr)> {
        let Stmt::If { cond, then_stmt, else_stmt: Some(e), .. } = s else {
            return None;
        };
        fn one(b: &Stmt) -> Option<(u32, &Expr)> {
            let l = flat_list(b);
            if l.len() == 1 {
                def_of(l[0])
            } else {
                None
            }
        }
        let (v1, e1) = one(then_stmt)?;
        let (v2, e2) = one(e)?;
        if v1 != v2 {
            return None;
        }
        Some((
            v1,
            Expr::Cond {
                c: Box::new(cond.clone()),
                t: Box::new(e1.clone()),
                f: Box::new(e2.clone()),
            },
        ))
    }

    // Prelude: defs (flat or folded cond), bare decls, side-effect stmts.
    let mut pmap: std::collections::HashMap<u32, Expr> =
        std::collections::HashMap::new();
    let mut pidx: std::collections::HashMap<u32, usize> =
        std::collections::HashMap::new();
    for (i, s) in stmts[..if_pos].iter().enumerate() {
        match s {
            Stmt::LocalDef { .. } | Stmt::ExprStmt(_) => {
                if let Some((v, e)) = def_of(s) {
                    pmap.insert(v, e.clone());
                    pidx.insert(v, i);
                }
            }
            Stmt::If { .. } => match cond_def_of(s) {
                Some((v, e)) => {
                    pmap.insert(v, e);
                    pidx.insert(v, i);
                }
                None => return false,
            },
            _ => return false,
        }
    }
    let (cond, then_v, else_v, had_else) = match &stmts[if_pos] {
        Stmt::If { cond, then_stmt, else_stmt, .. } => (
            cond.clone(),
            then_stmt.as_ref().clone(),
            else_stmt.as_ref().map_or_else(|| Stmt::Block(Vec::new()), |e| e.as_ref().clone()),
            else_stmt.is_some(),
        ),
        _ => return false,
    };
    // Chained guards (Kotlin multi-param null-checks):
    // `if(a){throw..} else { if(b){throw..} else { super(..); .. } }` —
    // a branch that is a lone delegation-bearing If gets merged
    // recursively first (its delegation hoisted to the branch head), so
    // the outer split then sees [call, nested-guard-remainder].
    fn normalize_branch(b: &mut Stmt) {
        // MOVE-based (no deep clone): chained weixin Parcel ctors carry
        // huge tails; cloning per recursion level cost measurable wall
        // time. merge_at leaves stmts untouched on failure, so the taken
        // node can always go back.
        let slot: &mut Stmt = match b {
            Stmt::Block(v) if v.len() == 1 => &mut v[0],
            other => other,
        };
        if !matches!(slot, Stmt::If { .. }) || !contains_delegation(slot) {
            return;
        }
        let taken = std::mem::replace(slot, Stmt::Block(Vec::new()));
        let mut tmp = vec![taken];
        if merge_at(&mut tmp, 0) {
            *slot = Stmt::Block(tmp);
        } else {
            *slot = tmp.pop().unwrap();
        }
    }
    let mut then_v = then_v;
    let mut else_v = else_v;
    normalize_branch(&mut then_v);
    normalize_branch(&mut else_v);
    let then_list = flat_list(&then_v);
    let else_list = flat_list(&else_v);

    // Exactly: two Call branches (merge with ternaries) or one Call +
    // one Clean (single-delegation throw-guard). Owned branch payloads.
    enum Side {
        Call {
            at: usize,
            defs: Vec<(u32, Expr)>,
            def_idxs: Vec<usize>,
        },
        Clean,
    }
    let (t_side, e_side, two_sided) = match (split_branch(&then_list), split_branch(&else_list)) {
        (Br::Call(tc, td, ti), Br::Call(ec, ed, ei)) => (
            Side::Call { at: tc, defs: td, def_idxs: ti },
            Side::Call { at: ec, defs: ed, def_idxs: ei },
            true,
        ),
        (Br::Call(tc, td, ti), Br::Clean) => (
            Side::Call { at: tc, defs: td, def_idxs: ti },
            Side::Clean,
            false,
        ),
        (Br::Clean, Br::Call(ec, ed, ei)) => (
            Side::Clean,
            Side::Call { at: ec, defs: ed, def_idxs: ei },
            false,
        ),
        _ => return false,
    };
    // The delegation nodes (two-sided: both; single: one).
    let (t_call, e_call) = match (&t_side, &e_side) {
        (Side::Call { at: ta, .. }, Side::Call { at: ea, .. }) => (
            ctor_call_expr(then_list[*ta]),
            ctor_call_expr(else_list[*ea]),
        ),
        (Side::Call { at: ta, .. }, Side::Clean) => {
            (ctor_call_expr(then_list[*ta]), None)
        }
        (Side::Clean, Side::Call { at: ea, .. }) => {
            (None, ctor_call_expr(else_list[*ea]))
        }
        _ => return false,
    };
    // The node that becomes the merged call: then side when present.
    let (call_list, call_at) = match &t_side {
        Side::Call { at, .. } => (&then_list, *at),
        Side::Clean => match &e_side {
            Side::Call { at, .. } => (&else_list, *at),
            Side::Clean => return false,
        },
    };
    let (base_args, other_args) = if two_sided {
        let (Some(tc), Some(ec)) = (t_call, e_call) else {
            return false;
        };
        if !same_ctor_kind(tc, ec) {
            return false;
        }
        let (Expr::Method { args: a1, .. }, Expr::Method { args: a2, .. }) = (tc, ec) else {
            return false;
        };
        if a1.len() != a2.len() {
            return false;
        }
        (a1, Some(a2))
    } else {
        let c = t_call.or(e_call);
        let Some(c) = c else { return false };
        let Expr::Method { args, .. } = c else {
            return false;
        };
        (args, None)
    };

    // Def maps per side (prelude + own branch defs).
    let mut tmap: std::collections::HashMap<u32, Expr> = pmap.clone();
    let mut emap: std::collections::HashMap<u32, Expr> = pmap.clone();
    if let Side::Call { defs, .. } = &t_side {
        for (v, e) in defs {
            tmap.insert(*v, e.clone());
        }
    }
    if let Side::Call { defs, .. } = &e_side {
        for (v, e) in defs {
            emap.insert(*v, e.clone());
        }
    }
    let Some(cond_i) = inline_locals(&cond, &pmap, 0) else {
        return false;
    };
    // Inline each side's args through its own map.
    let mut then_args: Vec<Expr> = Vec::with_capacity(base_args.len());
    let mut else_args: Vec<Expr> = Vec::new();
    if two_sided {
        for a in base_args {
            match inline_locals(a, &tmap, 0) {
                Some(r) => then_args.push(r),
                None => return false,
            }
        }
        for a in other_args.unwrap() {
            match inline_locals(a, &emap, 0) {
                Some(r) => else_args.push(r),
                None => return false,
            }
        }
    } else {
        // Single-delegation side: base_args belong to whichever side
        // carries the call; pick that side's map.
        let from_then = matches!(&t_side, Side::Call { .. });
        for a in base_args {
            let r = if from_then {
                inline_locals(a, &tmap, 0)
            } else {
                inline_locals(a, &emap, 0)
            };
            match r {
                Some(r) => then_args.push(r),
                None => return false,
            }
        }
    }
    let primary_args = base_args;
    // Per-position merge.
    let mut merged: Vec<Expr> = Vec::with_capacity(then_args.len());
    let mut differ = 0usize;
    for (j, t) in then_args.iter().enumerate() {
        if two_sided {
            let e = &else_args[j];
            if t == e {
                merged.push(t.clone());
            } else {
                differ += 1;
                merged.push(Expr::Cond {
                    c: Box::new(cond_i.clone()),
                    t: Box::new(t.clone()),
                    f: Box::new(e.clone()),
                });
            }
        } else {
            merged.push(t.clone());
        }
    }

    // ---- side-effect preservation guards (batched counts) ----
    let vars_in = |e: &Expr| -> Vec<u32> {
        let mut vs = Vec::new();
        let mut probe = e.clone();
        strip_lost_alloc_owners(&mut probe);
        deep_rewrite(&mut probe, &mut |x| {
            if let Expr::Local { var, .. } = x {
                if !vs.contains(var) {
                    vs.push(*var);
                }
            }
        });
        vs
    };
    // Remainder statements per branch (extras + post-call tail; a Clean
    // branch contributes all of its statements).
    // The consumed defs LEAVE the remainder: their expressions were
    // inlined into the merged delegation args, and a dead `v = E` left
    // after the call both reads wrong and trips the u_t1/u_t2 guards
    // (ContinuationImpl's branch-local `context = null / getContext()`
    // — the coroutine family's 对this的调用必须是第一个语句 root).
    let branch_remainder = |list: &[&Stmt], side: &Side| -> Vec<Stmt> {
        match side {
            Side::Clean => list.iter().map(|s| (*s).clone()).collect(),
            Side::Call { at, def_idxs, .. } => {
                list.iter()
                    .enumerate()
                    .filter(|(i, _)| *i != *at && !def_idxs.contains(i))
                    .map(|(_, s)| (*s).clone())
                    .collect()
            }
        }
    };
    let tail_then_v = branch_remainder(&then_list, &t_side);
    let tail_else_v = branch_remainder(&else_list, &e_side);
    let post = &stmts[if_pos + 1..];
    let mut inlined: Vec<u32> = vars_in(&cond);
    for a in primary_args.iter().chain(else_args.iter()) {
        for v in vars_in(a) {
            if !inlined.contains(&v) {
                inlined.push(v);
            }
        }
    }
    inlined.retain(|v| pmap.contains_key(v) || tmap.contains_key(v) || emap.contains_key(v));
    // Prelude-and-branch redefinition: ambiguous provenance — reject.
    for &v in &inlined {
        let in_branch = match (&t_side, &e_side) {
            (Side::Call { defs: td, .. }, Side::Call { defs: ed, .. }) => {
                td.iter().any(|(d, _)| *d == v) || ed.iter().any(|(d, _)| *d == v)
            }
            (Side::Call { defs, .. }, Side::Clean)
            | (Side::Clean, Side::Call { defs, .. }) => {
                defs.iter().any(|(d, _)| *d == v)
            }
            _ => false,
        };
        if pmap.contains_key(&v) && in_branch {
            return false;
        }
    }
    type Counts = std::collections::HashMap<u32, usize>;
    type GuardCounts = (
        Counts,
        Vec<Counts>,
        Vec<Counts>,
        Counts,
        Counts,
        Counts,
        Vec<(u32, Counts)>,
    );
    let (cond_counts, a1_counts, a2_counts, tail1_counts, tail2_counts, post_counts, def_counts): GuardCounts =
        if inlined.is_empty() {
        Default::default()
    } else {
        let all_defs: Vec<(u32, &Expr)> = pmap
            .iter()
            .map(|(k, v)| (*k, v))
            .chain(match &t_side {
                Side::Call { defs, .. } => defs.iter().map(|(k, v)| (*k, v)).collect(),
                Side::Clean => Vec::new(),
            })
            .chain(match &e_side {
                Side::Call { defs, .. } => defs.iter().map(|(k, v)| (*k, v)).collect(),
                Side::Clean => Vec::new(),
            })
            .collect();
        (
            count_locals_expr(&cond),
            primary_args.iter().map(count_locals_expr).collect(),
            else_args.iter().map(count_locals_expr).collect(),
            count_locals_stmts(&tail_then_v),
            count_locals_stmts(&tail_else_v),
            count_locals_stmts(post),
            all_defs.into_iter().map(|(v, e)| (v, count_locals_expr(e))).collect(),
        )
        };
    for &v in &inlined {
        let in_t = matches!(&t_side, Side::Call { defs, .. } if defs.iter().any(|(d, _)| *d == v));
        let in_e = matches!(&e_side, Side::Call { defs, .. } if defs.iter().any(|(d, _)| *d == v));
        let effectful = [
            in_t.then(|| tmap.get(&v)).flatten(),
            in_e.then(|| emap.get(&v)).flatten(),
            pmap.get(&v),
        ]
        .into_iter()
        .flatten()
        .any(jdc_core::ir::build::has_side_effects);
        if !effectful {
            continue;
        }
        let u_cond = cnt(&cond_counts, v);
        let u_post = cnt(&post_counts, v);
        let u_t1 = cnt(&tail1_counts, v);
        let u_t2 = cnt(&tail2_counts, v);
        let mut u_odef = 0usize;
        for (dv, dc) in &def_counts {
            if *dv != v && inlined.contains(dv) {
                u_odef += cnt(dc, v);
            }
        }
        let mut emit = u_cond * (1 + differ);
        let mut uses_args = 0usize;
        for j in 0..primary_args.len() {
            let c1 = cnt(&a1_counts[j], v);
            let c2 = if two_sided && j < a2_counts.len() {
                cnt(&a2_counts[j], v)
            } else {
                0
            };
            uses_args += c1 + c2;
            emit += if two_sided && then_args[j] != else_args[j] {
                c1 + c2
            } else {
                c1.max(c2)
            };
        }
        let ok = if in_t || in_e {
            u_cond == 0
                && u_post == 0
                && u_t1 == 0
                && u_t2 == 0
                && u_odef == 0
                && a1_counts.iter().map(|c| cnt(c, v)).sum::<usize>() <= 1
                && a2_counts.iter().map(|c| cnt(c, v)).sum::<usize>() <= 1
                && emit <= 2
                && (in_t || a1_counts.iter().all(|c| cnt(c, v) == 0))
                && (in_e || a2_counts.iter().all(|c| cnt(c, v) == 0))
        } else {
            u_post == 0
                && u_t1 == 0
                && u_t2 == 0
                && u_odef == 0
                && ((u_cond == 1 && uses_args == 0 && emit <= 2)
                    || (u_cond == 0 && emit <= 1))
        };
        if !ok {
            return false;
        }
    }

    // ---- assembly ----
    let mut call_stmt = call_list[call_at].clone();
    if let Stmt::ExprStmt(Expr::Method { args: slot, .. }) = &mut call_stmt {
        *slot = merged;
    }
    let residual = |v: u32| -> usize {
        cnt(&tail1_counts, v) + cnt(&tail2_counts, v) + cnt(&post_counts, v)
    };
    let mut kept_prelude: Vec<Stmt> = Vec::new();
    for (i, s) in stmts[..if_pos].iter().enumerate() {
        let consumed = match s {
            Stmt::LocalDef { var, .. } => Some(*var),
            Stmt::ExprStmt(Expr::Assign { target, .. }) => match &**target {
                Expr::Local { var, .. } => Some(*var),
                _ => None,
            },
            Stmt::If { .. } => cond_def_of(s).map(|(v, _)| v),
            _ => None,
        };
        if let Some(v) = consumed {
            if inlined.contains(&v) && pidx.get(&v) == Some(&i) && residual(v) == 0 {
                continue;
            }
        }
        kept_prelude.push(s.clone());
    }
    let build_keep = |list: &[&Stmt], side: &Side| -> Vec<Stmt> {
        match side {
            Side::Clean => list.iter().map(|s| (*s).clone()).collect(),
            Side::Call { at, .. } => {
                let mut out = Vec::new();
                for (i, s) in list.iter().enumerate() {
                    if i == *at {
                        continue;
                    }
                    if i < *at {
                        if let Some((v, _)) = def_of(s) {
                            if inlined.contains(&v) && residual(v) == 0 {
                                continue;
                            }
                        }
                    }
                    out.push((*s).clone());
                }
                out
            }
        }
    };
    let then_keep = build_keep(&then_list, &t_side);
    let else_keep = build_keep(&else_list, &e_side);
    let else_part = if else_keep.is_empty() && !had_else {
        None
    } else {
        Some(Box::new(Stmt::Block(else_keep)))
    };
    let new_if = Stmt::If {
        cond: cond_i,
        then_stmt: Box::new(Stmt::Block(then_keep)),
        else_stmt: else_part,
    };
    let if_empty = match &new_if {
        Stmt::If { then_stmt, else_stmt, .. } => {
            let be = |s: &Stmt| matches!(s, Stmt::Block(v) if v.is_empty());
            be(then_stmt) && else_stmt.as_ref().is_none_or(|e| be(e))
        }
        _ => false,
    };
    let mut out: Vec<Stmt> = Vec::with_capacity(stmts.len());
    out.push(call_stmt);
    out.extend(kept_prelude);
    if !if_empty {
        out.push(new_if);
    }
    out.extend(stmts[if_pos + 1..].to_vec());
    *stmts = out;
    true
}


pub fn strip_enum_ctor_super(body: &mut Stmt) {
    let is_enum_super = |s: &Stmt| {
        matches!(
            s,
            Stmt::ExprStmt(Expr::Method { name, is_super: true, .. }) if &**name == "<init>"
        )
    };
    let Stmt::Block(stmts) = body else {
        return;
    };
    stmts.retain(|s| !is_enum_super(s));
    for st in stmts.iter_mut() {
        if let Stmt::Block(inner) = st {
            inner.retain(|s| !is_enum_super(s));
        }
    }
}

pub fn ensure_declared(body: &mut Stmt, vt: &VarTable) {
    // (Perf: dense Vec<bool> tables instead of HashSets — var ids are
    // dense; the `assigned` set collected here was never read and cost a
    // full extra tree walk per method.)
    let n = vt.vars.len().max(1);

    // Demote extra LocalDefs (same var declared more than once) FIRST —
    // the scope analysis below must see exactly one def per var.
    let mut seen: HashSet<u32> = HashSet::default();
    demote_dup_decls(body, &mut seen, vt);

    // Scope hoist: a LocalDef inside a nested block whose var is also
    // referenced OUTSIDE that block is a Java scope violation (the
    // branch-local `int v8 = pi.versionCode;` read after the try —
    // "cannot find symbol" at every outside use). Demote those defs to
    // assignments and let the bare top-of-method declaration below cover
    // the var. Two cheap passes: pre-order block numbering + per-var
    // inside/outside occurrence counts (pre-order subtree = id range).
    let mut def_block: Vec<u32> = vec![u32::MAX; n];
    let mut sizes: Vec<u32> = vec![0];
    let mut next_id: u32 = 1;
    scope_pass_a(body, 0, &mut next_id, &mut def_block, &mut sizes);
    sizes[0] = next_id;
    let mut within: Vec<u32> = vec![0; n];
    let mut total: Vec<u32> = vec![0; n];
    let mut next_b: u32 = 1;
    scope_pass_b(body, 0, &mut next_b, &def_block, &sizes, &mut within, &mut total);
    let mut hoist: HashSet<u32> = HashSet::default();
    for v in 0..n {
        if def_block[v] != u32::MAX && def_block[v] != 0 && within[v] < total[v] {
            hoist.insert(v as u32);
        }
    }
    if !hoist.is_empty() {
        let mut seed: HashSet<u32> = hoist.iter().copied().collect();
        demote_dup_decls(body, &mut seed, vt);
    }

    let mut declared: Vec<bool> = vec![false; n];
    let mut is_param: Vec<bool> = vec![false; n];
    for v in &vt.vars {
        if v.is_param && (v.id as usize) < n {
            is_param[v.id as usize] = true;
        }
    }
    // Catch parameters are declared by the `catch (Type v)` clause —
    // bind_catches consumed their LocalDef before this pass ran, so
    // without this they re-declare at the top of the method and clash
    // with the clause (`Throwable th2;` + `catch (Throwable th2)` — a
    // syntax gate cannot see this, it is a semantic "already defined").
    let mut is_catch: Vec<bool> = vec![false; n];
    walk_all(body, &mut |st| {
        if let Stmt::Try { catches, .. } = st {
            for c in catches {
                if (c.var as usize) < n {
                    is_catch[c.var as usize] = true;
                }
            }
        }
    });
    walk_all(body, &mut |st| {
        if let Stmt::LocalDef { var, .. } = st {
            if (*var as usize) < n {
                declared[*var as usize] = true;
            }
        }
    });
    let mut used: HashSet<u32> = HashSet::default();
    // assignments=true: a var that only ever appears as an assign
    // TARGET still needs a declaration (`x = 5;` alone does not
    // declare x in Java).
    stmt_collect_vars(body, &mut used, true);

    // Params are declared by the signature; hoisted vars lost their
    // LocalDef to the demotion above and always need the bare decl.
    let mut needs_decl: Vec<u32> = used
        .into_iter()
        .filter(|v| {
            let i = *v as usize;
            i >= n
                || ((!declared[i] && !is_param[i] && !is_catch[i]) || hoist.contains(v))
        })
        .collect();
    needs_decl.sort_unstable();
    needs_decl.dedup();

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

// ---------------------------------------------------------------------------
// jadx-style local names (ApplyVariableNames + dexdec's port of it)
// ---------------------------------------------------------------------------

/// A synthetic `v12`/`p3` never survives when a better name exists.
/// Priority: (1) a Kotlin `Intrinsics.checkNotNullParameter(x, "name")`
/// names `x` from the message string (the string IS the parameter name);
/// (2) the single defining call — `getFoo()` → `foo`, `isFinishing()` →
/// `finishing`, `new File(…)` → `file`; (3) a type alias or the
/// lowercased class simple name. Collisions take `2`, `3`, …; a var with
/// two DISAGREEING defining calls stays unnamed (dexdec's
/// RelationalNameInference rule). Debug-info names are never touched
/// (`synthetic_name` gates the whole pass).
pub fn apply_local_names(vt: &mut VarTable, body: &Stmt) {
    use std::collections::{HashMap, HashSet};

    // ---- proposals ------------------------------------------------------
    // var → (name, source-priority); disagreeing call names are dropped.
    let mut by_call: HashMap<u32, Vec<String>> = HashMap::new();
    let mut by_intrinsics: HashMap<u32, String> = HashMap::new();

    visit_all_exprs(body, &mut |e| {
        if let Expr::Method { cls, name, args, .. } = e {
            if (cls.as_ref() == "kotlin/jvm/internal/Intrinsics"
                || cls.as_ref() == "kotlin/jvm/internal/IntrinsicsKt")
                && matches!(name.as_ref(), "checkNotNullParameter" | "checkParameterIsNotNull")
                && args.len() == 2
            {
                if let (Expr::Local { var, .. }, Expr::Const(ConstVal::Str(s))) = (&args[0], &args[1])
                {
                    by_intrinsics
                        .entry(*var)
                        .or_insert_with(|| sanitize_name(s).unwrap_or_default());
                }
            }
        }
    });

    walk_all(body, &mut |st| {
        let (var, value) = match st {
            Stmt::LocalDef { var, init: Some(e), .. } => (*var, e),
            Stmt::ExprStmt(Expr::Assign { target, value, .. })
                if matches!(&**target, Expr::Local { .. }) =>
            {
                let Expr::Local { var, .. } = &**target else { return };
                (*var, value.as_ref())
            }
            _ => return,
        };
        if let Some(n) = defining_call_name(value) {
            by_call.entry(var).or_default().push(n);
        }
    });

    // ---- reservation + application --------------------------------------
    // Real (debug-info) names can legally REPEAT across sibling source
    // scopes (`int i` in two loops) but our flat declaration hoisting
    // puts them in one scope — de-duplicate with the same numeric
    // suffixes the claim path uses.
    // Uniqueness operates on the SANITIZED display name: the identifier
    // sanitizer maps non-ASCII to `_`, so distinct debug names
    // (`ERROR_token参数缺失` / `ERROR_channelId参数缺失`) both RENDER as
    // `ERROR________` and collide as declarations. Tracking raw names
    // here would let the collision through.
    let sanit = |n: &str| crate::classdec::java_ident(n).into_owned();
    let mut taken: HashSet<String> = HashSet::default();
    // Parameter names are occupied REGARDLESS of syntheticness: claim()
    // hands out rename candidates, and without the synthetic params in
    // the pool a type fallback (`l7.p0` → "p0") renamed one parameter
    // ONTO another's slot-name (`b(v6.l p0, Object obj, l7.p0 p0)`).
    for v in vt.vars.iter() {
        // ALL synthetic names occupy their names, not just parameters:
        // a type fallback (`pc5.v56` → "v56") otherwise renames a local
        // ONTO another local's slot-name (`int v56;` beside
        // `pc5.v56 v56;`).
        if v.synthetic_name {
            taken.insert(sanit(&v.name));
        }
    }
    for v in vt.vars.iter_mut() {
        if v.synthetic_name {
            continue;
        }
        if !taken.insert(sanit(&v.name)) {
            let base = sanit(&v.name);
            for i in 2.. {
                let cand = format!("{base}{i}");
                if taken.insert(cand.clone()) {
                    v.name = cand;
                    break;
                }
            }
        }
    }
    let claim = |taken: &mut HashSet<String>, want: &str| -> String {
        let w = crate::classdec::java_ident(want).into_owned();
        if taken.insert(w.clone()) {
            return w;
        }
        for i in 2.. {
            let cand = format!("{w}{i}");
            if taken.insert(cand.clone()) {
                return cand;
            }
        }
        w
    };

    for info in vt.vars.iter_mut() {
        if !info.synthetic_name {
            continue;
        }
        // (1) Intrinsics string — the Kotlin compiler wrote the real
        // parameter name right into the check.
        if let Some(n) = by_intrinsics.get(&info.id) {
            if !n.is_empty() {
                info.name = claim(&mut taken, n);
                continue;
            }
        }
        // (2) One consistent defining call.
        if let Some(names) = by_call.get(&info.id) {
            let unique: HashSet<&String> = names.iter().collect();
            if unique.len() == 1 {
                let n = unique.into_iter().next().unwrap();
                if !is_java_keyword(n) {
                    info.name = claim(&mut taken, n);
                    continue;
                }
            }
        }
        // (3) Type alias, else the lowercased simple class name
        // (jadx names a `Looper` local `looper`).
        let want = type_alias(&info.ty).map(str::to_string).or_else(|| simple_type_name(&info.ty));
        if let Some(n) = want {
            info.name = claim(&mut taken, &n);
        }
    }

    // Final uniquification across ALL vars (params, locals, catch): the
    // reservation, claim and debug-name domains above are checked
    // pairwise but a name claimed LAST can still equal a debug name
    // that never re-checked (`zd1.v2 v2` beside `zd1.v2[] v2`).
    let mut seen: HashSet<String> = HashSet::default();
    for v in vt.vars.iter_mut() {
        if !seen.insert(sanit(&v.name)) {
            let base = sanit(&v.name);
            for i in 2.. {
                let cand = format!("{base}{i}");
                if seen.insert(cand.clone()) {
                    v.name = cand;
                    break;
                }
            }
        }
    }
}

/// `com/android/.../Looper` → `looper` — the alias-table fallback.
fn simple_type_name(ty: &TypeRef) -> Option<String> {
    let TypeRef::J(JavaType::Object(n)) = ty else {
        return None;
    };
    let simple = n.rsplit('/').next().unwrap_or(n);
    let simple = simple.rsplit('$').next().unwrap_or(simple);
    // Lowercase the first ALPHABETIC char — `$`/`_`-prefixed names
    // (R8's `$$$_Thread`) must not survive capitalized.
    let mut chars = simple.chars();
    let mut out = String::with_capacity(simple.len());
    let mut lowered = false;
    for c in chars.by_ref() {
        if c.is_ascii_alphabetic() && !lowered {
            out.push(c.to_ascii_lowercase());
            lowered = true;
        } else {
            out.push(c);
        }
        if lowered {
            break;
        }
    }
    out.extend(chars);
    sanitize_name(&out)
}

/// `getFoo()` → `foo`, `isFinishing()` → `finishing`, `new File(…)` →
/// `file`. The get/is prefixes only strip when the remainder starts
/// uppercase (so `issues()` keeps its name).
fn defining_call_name(e: &Expr) -> Option<String> {
    match e {
        Expr::Method { name, .. } => {
            let base = name
                .strip_prefix("get")
                .or_else(|| name.strip_prefix("is"))
                .filter(|rest| rest.chars().next().is_some_and(|c| c.is_ascii_uppercase()))
                .unwrap_or(name);
            let first = base.chars().next()?;
            let mut out = String::with_capacity(base.len());
            out.push(first.to_ascii_lowercase());
            out.extend(base.chars().skip(1));
            sanitize_name(&out)
        }
        Expr::New { cls, .. } => {
            let simple = cls.rsplit('/').next().unwrap_or(cls);
            let simple = simple.rsplit('$').next().unwrap_or(simple);
            let first = simple.chars().next()?;
            let mut out = String::with_capacity(simple.len());
            out.push(first.to_ascii_lowercase());
            out.extend(simple.chars().skip(1));
            sanitize_name(&out)
        }
        _ => None,
    }
}

/// Valid java identifier, not a keyword/restricted name, ≥2 chars.
fn sanitize_name(s: &str) -> Option<String> {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        if c.is_ascii_alphanumeric() || c == '_' || c == '$' {
            out.push(c);
        } else {
            out.push('_');
        }
    }
    if out.len() < 2
        || out.chars().next().is_some_and(|c| c.is_ascii_digit())
        || is_java_keyword(&out)
    {
        return None;
    }
    Some(out)
}

/// jadx's alias table for the common types, with the Android globals the
/// corpus actually shows; anything else falls back in the caller.
fn type_alias(ty: &TypeRef) -> Option<&'static str> {
    let TypeRef::J(JavaType::Object(n)) = ty else {
        return None;
    };
    Some(match n.as_ref() {
        "java/lang/String" | "kotlin/String" => "str",
        "java/lang/Class" => "cls",
        "java/lang/Throwable" => "th",
        "java/lang/Object" | "kotlin/Any" => "obj",
        "java/util/Iterator" | "kotlin/collections/Iterator" => "it",
        "java/lang/Boolean" => "bool",
        "java/lang/Integer" => "num",
        "java/lang/Character" => "ch",
        "java/lang/Byte" => "b",
        "java/lang/Short" => "sh",
        "java/lang/Float" => "f",
        "java/lang/Double" => "d",
        "java/lang/Long" => "i",
        "java/lang/StringBuilder" => "sb",
        "java/util/ArrayList" => "list",
        "java/util/HashMap" => "map",
        "android/content/Context" => "context",
        "android/content/Intent" => "intent",
        "android/os/Bundle" => "bundle",
        "android/view/View" => "view",
        "android/graphics/Bitmap" => "bitmap",
        "android/view/ViewGroup" => "viewGroup",
        _ => return None,
    })
}

/// Every expression in the tree, statements included (read-only).
fn visit_all_exprs<F: FnMut(&Expr)>(s: &Stmt, f: &mut F) {
    walk_all(s, &mut |st| {
        let exprs: Vec<&Expr> = match st {
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
            Stmt::If { cond, .. } | Stmt::While { cond, .. } | Stmt::DoWhile { cond, .. } => {
                vec![cond]
            }
            _ => Vec::new(),
        };
        for e in exprs {
            visit_exprs(e, f);
        }
    });
}

/// IntDef/LongDef exact-match rendering: a literal argument to a
/// platform method whose parameter carries a constant domain renders as
/// the named constant (`setVisibility(8)` → `android.view.View.GONE`).
/// Combined flag values and literals outside the domain stay numeric.
pub fn platform_constants(body: &mut Stmt) {
    if !crate::platform::installed() {
        return;
    }
    rewrite_exprs(body, &mut |e| {
        if let Expr::Method { cls, name, desc, args, .. } = e {
            for a in args.iter_mut() {
                let (value, is_long) = match a {
                    Expr::Const(ConstVal::Int(v)) => (*v as i64, false),
                    Expr::Const(ConstVal::Long(v)) => (*v, true),
                    _ => continue,
                };
                if let Some(named) =
                    crate::platform::named_constant(cls, name, &desc_to_string(desc), 0, value)
                {
                    let _ = is_long;
                    *a = Expr::Raw(named);
                }
            }
        }
    });
}

/// MethodDescriptor → dex descriptor string (`(I)V`).
fn desc_to_string(d: &jdc_core::types::MethodDescriptor) -> String {
    let mut out = String::from("(");
    for a in &d.args {
        type_to_desc(a, &mut out);
    }
    out.push(')');
    type_to_desc(&d.ret, &mut out);
    out
}

fn type_to_desc(t: &jdc_core::types::JavaType, out: &mut String) {
    match t {
        JavaType::Void => out.push('V'),
        JavaType::Boolean => out.push('Z'),
        JavaType::Byte => out.push('B'),
        JavaType::Char => out.push('C'),
        JavaType::Short => out.push('S'),
        JavaType::Int => out.push('I'),
        JavaType::Float => out.push('F'),
        JavaType::Long => out.push('J'),
        JavaType::Double => out.push('D'),
        JavaType::Object(n) => {
            out.push('L');
            out.push_str(n);
            out.push(';');
        }
        JavaType::Array(inner) => {
            out.push('[');
            type_to_desc(inner, out);
        }
    }
}

/// Kotlin `Intrinsics` null-check elision (jadx's ProcessKotlinInternals):
/// statement-position `checkNotNullParameter(p, "name")` /
/// `checkParameterIsNotNull` / `checkNotNull…` calls are runtime
/// assertions — drop them. The naming pass harvests the parameter
/// strings FIRST, so run this after `apply_local_names`.
pub fn remove_kotlin_checks(s: &mut Stmt) {
    walk_mut_deep(s, &mut |st| {
        let Stmt::Block(v) = st else { return };
        v.retain(|x| !is_kotlin_check(x));
    });
}

fn is_kotlin_check(s: &Stmt) -> bool {
    let Stmt::ExprStmt(e) = s else { return false };
    let Expr::Method { cls, name, .. } = e else { return false };
    (cls.as_ref() == "kotlin/jvm/internal/Intrinsics" || cls.as_ref() == "kotlin/jvm/internal/IntrinsicsKt__Jdk7Kt")
        && matches!(
            name.as_ref(),
            "checkNotNullParameter"
                | "checkParameterIsNotNull"
                | "checkExpressionValueIsNotNull"
                | "checkNotNullExpressionValue"
                | "checkReturnedValueIsNotNull"
                | "checkFieldIsNotNull"
                | "checkNotNull"
        )
}

// ---------------------------------------------------------------------------
// Synthetic-accessor inlining (jadx's MarkMethodsForInline, the safe subset)
// ---------------------------------------------------------------------------

/// Inline `access$NNN`-style synthetic static bridges at their call
/// sites: an identity (`return pN`), a getter (`iget pX, field;
/// return vR`), or a method forwarder (`invoke; return`) — with the
/// d8 APM trace wrappers (`MethodCollector.i/.o` const-only static
/// calls) tolerated around the core. Only STATIC + SYNTHETIC callees
/// qualify (compiler-generated bridges: no override semantics, no
/// side effects beyond the forwarded operation).
/// Can `host` (internal class name) source-level reference `target`'s
/// class chain and member? Cross-package inlining of a synthetic
/// accessor used to EXPOSE package-private targets the raw dex never
/// referenced cross-package (BuildersKt.launch$default forwards to
/// kotlinx.coroutines.k.e — the widening census cannot see post-inline
/// calls; lark's 1,019-line k不是公共的 family). Non-public chain link
/// or non-public member across packages → the inline must not happen
/// (the public synthetic bridge stays and compiles).
fn inline_ref_ok(pool: &DexPool, host: &str, target: &str, member: Option<(&str, bool)>) -> bool {
    let hpkg = match host.rfind('/') {
        Some(i) => &host[..i],
        None => "",
    };
    let mut cur = target;
    loop {
        let tpkg = match cur.rfind('/') {
            Some(i) => &cur[..i],
            None => "",
        };
        if tpkg != hpkg {
            if let Some(pc) = pool.get(cur) {
                if pc.access & crate::access::ACC_PUBLIC == 0 {
                    return false;
                }
                if cur == target {
                    if let Some((mname, is_method)) = member {
                        let ok = if is_method {
                            pc.all_methods().any(|m| {
                                &*m.name == mname
                                    && m.access & crate::access::ACC_PUBLIC != 0
                            })
                        } else {
                            pc.static_fields
                                .iter()
                                .chain(pc.instance_fields.iter())
                                .any(|f| {
                                    f.name == mname
                                        && f.access & crate::access::ACC_PUBLIC != 0
                                })
                        };
                        // A member match requires the exact member to be
                        // public; an absent member (renamed/collapsed)
                        // stays allowed — the render will show what the
                        // pool has.
                        if !ok
                            && (if is_method {
                                pc.all_methods().any(|m| &*m.name == mname)
                            } else {
                                pc.static_fields
                                    .iter()
                                    .chain(pc.instance_fields.iter())
                                    .any(|f| f.name == mname)
                            })
                        {
                            return false;
                        }
                    }
                }
            }
        }
        match cur.rfind('$') {
            Some(i) if i > 0 => cur = &cur[..i],
            _ => break,
        }
    }
    true
}

pub fn inline_accessors(s: &mut Stmt, pool: &DexPool, host: &str) {
    rewrite_exprs(s, &mut |e| {
        let Expr::Method { cls, name, desc, args, is_static, .. } = e else { return };
        if !*is_static || args.is_empty() {
            return;
        }
        let Some(target) = pool.get(cls) else { return };
        let desc_s = desc_to_string(desc);
        let Some(m) = target.find_method(name, &desc_s) else { return };
        if !(m.is_static() && m.access & access::ACC_SYNTHETIC != 0) {
            return;
        }
        let Some(dex) = pool.dex(m.dex_idx) else { return };
        // Snapshot first: the accessor's owning image may already be
        // retired, and a live read's success would depend on worker
        // completion interleaving — nondeterministic inlining (whether
        // the accessor folds at all) between identical runs.
        let code = match pool.accessor_code(m.dex_idx, m.code_off) {
            Some(bytes) => ddc_dex::CodeItem::parse(&bytes, 0),
            None => dex.code_at(m.code_off),
        };
        let Some(code) = code else { return };
        let insns: Vec<&Insn> =
            code.insns.iter().filter(|i| !matches!(i.kind, InsnKind::Nop)).collect();
        // Strip the APM trace wrappers (const-only invoke-static).
        let core: Vec<&Insn> = insns
            .iter()
            .copied()
            .filter(|i| !is_const_only_trace(&i.kind, &insns))
            .collect();
        match accessor_shape(&dex, &core, &code) {
            Some(Shape::Identity(arg_i)) => {
                if let Some(a) = args.get(arg_i) {
                    *e = a.clone();
                }
            }
            Some(Shape::FieldRead { arg, cls: field_cls, field, field_ty }) => {
                if !inline_ref_ok(pool, host, &field_cls, Some((&field, false))) {
                    return;
                }
                if let Some(owner) = args.get(arg).cloned().map(Box::new) {
                    let ty = TypeRef::J(desc_type(&field_ty));
                    // The inlined read must consult the member rename
                    // registry like every lifted field ref does — the
                    // raw dex name desynced from renamed declarations
                    // (lark uu4/f$b's `a`→`ax6`: 找不到符号 变量 a ×4.4k
                    // when the nested-collision deshadow fired).
                    let name = jdc_core::rename::field_display(
                        &field_cls,
                        &field,
                        &field_ty,
                    )
                    .map(std::sync::Arc::from)
                    .unwrap_or_else(|| field.into());
                    *e = Expr::Field {
                        owner: Some(owner),
                        cls: field_cls.into(),
                        name,
                        ty,
                        is_static: false,
                    };
                }
            }
            Some(Shape::Forward { cls: tcls, name: tname, desc: tdesc, instance }) => {
                if !inline_ref_ok(pool, host, &tcls, Some((&tname, true))) {
                    return;
                }
                // Same registry duty as FieldRead: the forwarded member
                // must render under its renamed display, not the raw
                // dex name.
                let disp = jdc_core::rename::field_display(
                    &tcls,
                    &tname,
                    &tdesc.to_string(),
                )
                .map(std::sync::Arc::from)
                .unwrap_or_else(|| tname.into());
                *cls = tcls.into();
                *name = disp;
                *desc = std::sync::Arc::new(tdesc);
                if instance && !args.is_empty() {
                    // The first param (the receiver) becomes the owner.
                    let recv = args.remove(0);
                    if let Expr::Method { owner, .. } = e {
                        *owner = Some(Box::new(recv));
                    }
                }
            }
            None => {}
        }
    });
}

/// What an accessor body reduces to.
enum Shape {
    /// `return pN` — the call becomes argument N.
    Identity(usize),
    /// `iget vR, pX, field; return vR` — becomes `argN.field`.
    FieldRead { arg: usize, cls: String, field: String, field_ty: String },
    /// `invoke {pX, args…}, method@M; (move-result;)? return` —
    /// becomes the forwarded call.
    Forward { cls: String, name: String, desc: MethodDescriptor, instance: bool },
}

/// Resolve the IGet field's owner class, name and type descriptor.
fn field_of(dex: &ddc_dex::DexFile, field_idx: u32) -> Option<(String, String, String)> {
    let f = dex.field(field_idx);
    Some((
        // class_name strips the `L...;` shell; type_name would leak a
        // descriptor into the Field's owner class (`La3.a.e_`).
        dex.class_name(f.class_idx),
        dex.string(f.name_idx).to_string(),
        // The FIELD TYPE stays a descriptor: desc_type parses it.
        dex.type_name(f.type_idx).to_string(),
    ))
}

/// Map a register to a parameter index (static method: params occupy
/// the LAST ins_size registers).
fn param_index(code: &ddc_dex::CodeItem, reg: u16) -> Option<usize> {
    let rs = code.registers_size as usize;
    let ins = code.ins_size as usize;
    let r = reg as usize;
    let first = rs.checked_sub(ins)?;
    (r >= first && r < rs).then(|| r - first)
}

fn accessor_shape(
    dex: &ddc_dex::DexFile,
    core: &[&Insn],
    code: &ddc_dex::CodeItem,
) -> Option<Shape> {
    // Dead consts that fed the stripped trace wrappers remain in the
    // core — skip them.
    let core: &[&Insn] = match core.split_first() {
        Some((first, rest)) if matches!(first.kind, InsnKind::Const { .. }) => rest,
        _ => core,
    };
    let core: &[&Insn] = match core.split_last() {
        Some((last, rest)) if matches!(last.kind, InsnKind::Const { .. }) => rest,
        _ => core,
    };
    match core {
        // return pN
        [Insn { kind: InsnKind::Return { src }, .. }] => {
            let idx = param_index(code, *src)?;
            Some(Shape::Identity(idx))
        }
        // iget vR, pX, field; return vR
        [
            Insn { kind: InsnKind::IGet { dst, obj, field_idx }, .. },
            Insn { kind: InsnKind::Return { src }, .. },
        ] if dst == src => {
            let arg = param_index(code, *obj)?;
            let (cls, field, field_ty) = field_of(dex, *field_idx)?;
            Some(Shape::FieldRead { arg, cls, field, field_ty })
        }
        // invoke {…}, method@M; (move-result; return)? — forwarder.
        [Insn { kind: InsnKind::Invoke { method_idx, regs, kind, .. }, .. }, rest @ ..] if rest.len() <= 2 => {
            // Only forward when every register is a param (no locals).
            if !regs.iter().all(|r| param_index(code, *r).is_some()) || regs.is_empty() {
                return None;
            }
            // Trailing must be move-result+return or return/void —
            // anything else (e.g. trace calls) already filtered upstream.
            if rest.len() == 2 {
                let ok = matches!(rest[0].kind, InsnKind::MoveResult { .. })
                    && matches!(rest[1].kind, InsnKind::Return { .. } | InsnKind::ReturnVoid);
                if !ok {
                    return None;
                }
            }
            let mid = dex.method(*method_idx);
            // class_name strips the `L...;` shell — type_name leaks a
            // descriptor into the forwarded call's class (`La3.a.e_`).
            let cls = dex.class_name(mid.class_idx);
            let name = dex.string(mid.name_idx).to_string();
            let mut s = String::from("(");
            for t in dex.proto_params(mid.proto_idx) {
                s.push_str(dex.type_name(*t));
            }
            s.push(')');
            s.push_str(dex.type_name(dex.proto(mid.proto_idx).return_type_idx));
            let desc = parse_method_descriptor(&s)?;
            Some(Shape::Forward { cls, name, desc, instance: !matches!(kind, InvokeKind::Static) })
        }
        _ => None,
    }
}


/// A const-only invoke-static (the d8 APM `i(732046)` / `o(732046)`
/// trace wrapper): every argument register is loaded by a Const (or a
/// Const-into-move chain) in the SAME body. Scoped to synthetic
/// accessors, so a genuinely side-effecting const call is never
/// mistaken for a trace.
fn is_const_only_trace(kind: &InsnKind, insns: &[&Insn]) -> bool {
    let InsnKind::Invoke { kind, regs, .. } = kind else { return false };
    if !matches!(kind, InvokeKind::Static) || regs.is_empty() {
        return false;
    }
    regs.iter().all(|r| const_loaded(*r, insns, 0))
}

/// Const-loaded directly, or through a Move chain from a const-loaded
/// register (the APM `const v0, id` → `invoke {v0}` shape).
fn const_loaded(r: u16, insns: &[&Insn], depth: u8) -> bool {
    if depth > 3 {
        return false;
    }
    insns.iter().any(|i| match &i.kind {
        InsnKind::Const { dst, .. } => *dst == r,
        InsnKind::Move { dst, src } => *dst == r && const_loaded(*src, insns, depth + 1),
        _ => false,
    })
}
