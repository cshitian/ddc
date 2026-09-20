//! The DEX front-end's implementation of `jdc_core::Ctx`.
//!
//! Every method here answers a *semantic* question about class metadata
//! using the pooled DEX class table; generics are absent (erased), so all
//! generic-aware queries answer "unknown" and the core degrades gracefully.

use jdc_core::ir::expr::{Expr, TypeRef};
use jdc_core::types::{
    ClassAccessFlags, FieldAccessFlags, GenericType, JavaType, MethodAccessFlags, MethodDescriptor,
};
use jdc_core::{Ctx, Family, NestedClass, NestedKind};

use crate::access::*;
use crate::{desc_type, DexPool, PoolClass};

/// Front-end context handed to the core's structurer and printer.
pub struct DexCtx<'a> {
    pub pool: &'a DexPool,
    pub class: &'a PoolClass,
}

impl<'a> DexCtx<'a> {
    pub fn new(pool: &'a DexPool, class: &'a PoolClass) -> Self {
        DexCtx { pool, class }
    }

    fn find_class(&self, internal: &str) -> Option<&PoolClass> {
        self.pool.get(internal)
    }

    /// Structural inner-class evidence: an instance field whose type IS
    /// the enclosing class (the this$0 outer reference; type-based so it
    /// survives field renames).
    fn holds_outer_ref(&self, internal: &str, pc: &PoolClass) -> bool {
        let Some(outer) = self.find_outer(internal) else {
            return false;
        };
        pc.instance_fields.iter().any(|f| {
            f.desc
                .strip_prefix('L')
                .and_then(|d| d.strip_suffix(';'))
                .is_some_and(|ty| ty == outer)
        })
    }

    /// Nesting evidence (see `find_outer_name`).
    fn outer_of(&self, internal: &str) -> Option<String> {
        crate::find_outer_name(self.pool, internal)
    }

    fn class_access_flags(&self, internal: &str) -> ClassAccessFlags {
        let mut f = ClassAccessFlags::empty();
        let Some(pc) = self.find_class(internal) else {
            return f;
        };
        let a = pc.access;
        if a & ACC_PUBLIC != 0 {
            f |= ClassAccessFlags::PUBLIC;
        }
        if a & ACC_FINAL != 0 {
            f |= ClassAccessFlags::FINAL;
        }
        if a & ACC_INTERFACE != 0 {
            f |= ClassAccessFlags::INTERFACE;
        }
        if a & ACC_ABSTRACT != 0 {
            f |= ClassAccessFlags::ABSTRACT;
        }
        if a & ACC_SYNTHETIC != 0 {
            f |= ClassAccessFlags::SYNTHETIC;
        }
        if a & ACC_ANNOTATION != 0 {
            f |= ClassAccessFlags::ANNOTATION;
        }
        if a & ACC_ENUM != 0 {
            f |= ClassAccessFlags::ENUM;
        }
        f
    }
}

impl<'a> Ctx for DexCtx<'a> {
    fn pool_id(&self) -> u64 {
        // Printer::shorten memo cache key: every DexCtx in a run shares
        // one DexPool, and shorten's ctx queries (has_class/find_outer/
        // class_bases) are pool-level — one cache entry set per pool.
        self.pool as *const DexPool as u64
    }

    fn class_name(&self) -> &str {
        &self.class.name
    }

    fn source_level(&self) -> u16 {
        52
    }

    fn find_outer(&self, internal: &str) -> Option<String> {
        if internal == self.class.name {
            return self.outer_of(internal);
        }
        self.outer_of(internal)
    }

    fn family(&self, root: &str) -> Family {
        let mut fam = Family {
            root: root.to_string(),
            ..Default::default()
        };
        // Cached child index: BFS over the `$` chain from `root`.
        let mut queue: std::collections::VecDeque<String> =
            self.pool.children_of(root).iter().cloned().collect();
        let mut seen: jdc_core::FxHashSet<String> = queue.iter().cloned().collect();
        while let Some(name) = queue.pop_front() {
            for c in self.pool.children_of(&name) {
                if seen.insert(c.clone()) {
                    queue.push_back(c.clone());
                }
            }
            let Some(_) = self.find_class(&name) else {
                continue;
            };
            let root_prefix = format!("{}$", root);
            let rest: String = if name.starts_with(&root_prefix) {
                name[root_prefix.len()..].to_string()
            } else {
                name.rsplit('$').next().unwrap_or(&name).to_string()
            };
            let simple = rest.rsplit('$').next().unwrap_or(&rest).to_string();
            let kind = classify_nested(&rest);
            let access = self.class_access_flags(&name);
            fam.nested.insert(
                name.clone(),
                NestedClass {
                    name: name.clone(),
                    simple,
                    kind,
                    access,
                    sig_header: None,
                },
            );
            match kind {
                NestedKind::Anonymous => {
                    fam.anonymous.insert(name.clone());
                }
                NestedKind::Local => {
                    fam.locals.insert(name.clone());
                }
                NestedKind::Lambda => {
                    fam.lambdas.insert(name.clone());
                }
                NestedKind::Member => {}
            }
        }
        fam
    }

    fn nested_is_static(&self, internal: &str) -> bool {
        match self.find_class(internal) {
            // ACC_STATIC (annotation evidence) OR the structural signal:
            // no instance field typed as the outer class. javac ALWAYS
            // gives a non-static inner class an enclosing-instance field
            // (this$0), and the field TYPE survives obfuscation that
            // renames the field itself. Plain d8 output carries no
            // nesting annotations at all — without the structural
            // fallback every static nested class rendered as an inner
            // one (`str.new Report(...)` swallowing the first ctor arg).
            Some(pc) => pc.is_static_nested() || !self.holds_outer_ref(internal, pc),
            None => true,
        }
    }

    fn class_has_this0(&self, internal: &str) -> bool {
        // Inner classes without ACC_STATIC carry an enclosing instance.
        match self.find_class(internal) {
            Some(pc) => !pc.is_static_nested() && self.holds_outer_ref(internal, pc),
            None => false,
        }
    }

    fn is_subtype_of(&self, sub: &JavaType, sup: &str) -> bool {
        if let JavaType::Object(n) = sub {
            self.pool.is_subtype(n, sup)
        } else {
            false
        }
    }

    fn is_interface(&self, internal: &str) -> bool {
        self.find_class(internal)
            .map(|pc| pc.is_interface())
            .unwrap_or(false)
    }

    fn is_sealed(&self, _internal: &str) -> bool {
        false
    }

    fn super_name(&self, internal: &str) -> Option<String> {
        self.find_class(internal)
            .and_then(|pc| pc.super_name.clone())
    }

    fn has_class(&self, internal: &str) -> bool {
        self.pool.get(internal).is_some() || internal == self.class.name
    }

    fn class_supers_args(
        &self,
        internal: &str,
        _args: &[GenericType],
    ) -> Vec<(String, Vec<GenericType>)> {
        let mut out = Vec::new();
        let mut cur = self.find_class(internal).map(|pc| pc.name.clone());
        let mut hops = 0;
        while let Some(name) = cur {
            hops += 1;
            if hops > 64 {
                break;
            }
            if name == "java/lang/Object" {
                break;
            }
            out.push((name.clone(), Vec::new()));
            cur = self.find_class(&name).and_then(|pc| pc.super_name.clone());
        }
        out
    }

    fn class_bases(&self, internal: &str) -> Option<(Vec<String>, Option<String>)> {
        let pc = self.find_class(internal)?;
        Some((pc.interfaces.clone(), pc.super_name.clone()))
    }

    fn field_flags(&self, internal: &str, name: &str) -> Option<FieldAccessFlags> {
        let pc = self.find_class(internal)?;
        let raw = pc
            .static_fields
            .iter()
            .chain(pc.instance_fields.iter())
            .find(|f| f.name == name)?
            .access;
        Some(raw_field_flags(raw))
    }

    fn method_flags(&self, internal: &str, name: &str, desc: &str) -> Option<MethodAccessFlags> {
        let pc = self.find_class(internal)?;
        let m = pc.find_method(name, desc)?;
        Some(raw_method_flags(m.access))
    }

    fn declares_field(&self, internal: &str, name: &str) -> bool {
        self.find_class(internal)
            .map(|pc| pc.field_flags_of(name).is_some())
            .unwrap_or(false)
    }

    fn declares_method_named(&self, internal: &str, name: &str) -> bool {
        self.find_class(internal)
            .map(|pc| pc.all_methods().any(|m| &*m.name == name))
            .unwrap_or(false)
    }

    fn is_generic_call(&self, _e: &Expr) -> bool {
        false
    }

    fn generic_call_formals(&self, _e: &Expr) -> Option<(Vec<GenericType>, Vec<String>)> {
        None
    }

    fn polymorphic_ret_cast(
        &self,
        _cls: &str,
        _name: &str,
        _desc: &MethodDescriptor,
    ) -> Option<JavaType> {
        None
    }

    fn ctor_formals_by_arity(&self, internal: &str, arity: usize) -> Option<Vec<GenericType>> {
        let pc = self.find_class(internal)?;
        let ctors = pc.ctors_by_arity(arity);
        let m = ctors.first()?;
        let md = m.parsed_desc()?;
        Some(md.args.iter().map(java_type_to_generic).collect())
    }

    fn ctor_param_types(
        &self,
        internal: &str,
        skip: usize,
        n: usize,
        args: &[Expr],
    ) -> Option<Vec<JavaType>> {
        let _ = args;
        let pc = self.find_class(internal)?;
        let ctors = pc.ctors_by_arity(skip + n);
        let m = ctors.first()?;
        let md = m.parsed_desc()?;
        Some(md.args.iter().skip(skip).cloned().collect())
    }

    fn outer_param_via_super(&self, _internal: &str) -> bool {
        false
    }

    fn nested_method(
        &self,
        _l: &jdc_core::ir::expr::LambdaExpr,
        _outer_vt: &jdc_core::var::VarTable,
    ) -> Option<jdc_core::MethodBody> {
        None
    }
}

/// `$`-suffix classification (javac conventions d8 preserves).
fn classify_nested(rest: &str) -> NestedKind {
    // rest is the text after `Outer$`.
    let tail = rest.rsplit('$').next().unwrap_or(rest);
    if rest.starts_with("-$$Lambda$") || tail.starts_with("-$$Lambda$") {
        return NestedKind::Lambda;
    }
    if !tail.is_empty() && tail.chars().all(|c| c.is_ascii_digit()) {
        return NestedKind::Anonymous;
    }
    if tail.starts_with(|c: char| c.is_ascii_digit()) {
        return NestedKind::Local;
    }
    NestedKind::Member
}

fn raw_field_flags(raw: u32) -> FieldAccessFlags {
    let mut f = FieldAccessFlags::empty();
    if raw & ACC_PUBLIC != 0 {
        f |= FieldAccessFlags::PUBLIC;
    }
    if raw & ACC_PRIVATE != 0 {
        f |= FieldAccessFlags::PRIVATE;
    }
    if raw & ACC_PROTECTED != 0 {
        f |= FieldAccessFlags::PROTECTED;
    }
    if raw & ACC_STATIC != 0 {
        f |= FieldAccessFlags::STATIC;
    }
    if raw & ACC_FINAL != 0 {
        f |= FieldAccessFlags::FINAL;
    }
    if raw & ACC_SYNTHETIC != 0 {
        f |= FieldAccessFlags::SYNTHETIC;
    }
    if raw & ACC_ENUM != 0 {
        f |= FieldAccessFlags::ENUM;
    }
    f
}

fn raw_method_flags(raw: u32) -> MethodAccessFlags {
    let mut f = MethodAccessFlags::empty();
    if raw & ACC_PUBLIC != 0 {
        f |= MethodAccessFlags::PUBLIC;
    }
    if raw & ACC_PRIVATE != 0 {
        f |= MethodAccessFlags::PRIVATE;
    }
    if raw & ACC_PROTECTED != 0 {
        f |= MethodAccessFlags::PROTECTED;
    }
    if raw & ACC_STATIC != 0 {
        f |= MethodAccessFlags::STATIC;
    }
    if raw & ACC_FINAL != 0 {
        f |= MethodAccessFlags::FINAL;
    }
    if raw & ACC_SYNCHRONIZED != 0 || raw & ACC_DECLARED_SYNCHRONIZED != 0 {
        f |= MethodAccessFlags::SYNCHRONIZED;
    }
    if raw & ACC_BRIDGE != 0 {
        f |= MethodAccessFlags::BRIDGE;
    }
    if raw & ACC_VARARGS != 0 {
        f |= MethodAccessFlags::VARARGS;
    }
    if raw & ACC_NATIVE != 0 {
        f |= MethodAccessFlags::NATIVE;
    }
    if raw & ACC_ABSTRACT != 0 {
        f |= MethodAccessFlags::ABSTRACT;
    }
    if raw & ACC_STRICT != 0 {
        f |= MethodAccessFlags::STRICT;
    }
    if raw & ACC_SYNTHETIC != 0 {
        f |= MethodAccessFlags::SYNTHETIC;
    }
    f
}

/// Erased JavaType → generic type view (no signature data in DEX).
pub fn java_type_to_generic(t: &JavaType) -> GenericType {
    match t {
        JavaType::Object(n) => GenericType::Class(class_sig_of(n)),
        JavaType::Array(inner) => GenericType::Array(Box::new(java_type_to_generic(inner))),
        other => GenericType::Primitive(other.primitive_char().unwrap_or('V')),
    }
}

fn class_sig_of(internal: &str) -> jdc_core::types::ClassSig {
    let (package, name) = match internal.rfind('/') {
        Some(i) => (internal[..i].to_string(), internal[i + 1..].to_string()),
        None => (String::new(), internal.to_string()),
    };
    jdc_core::types::ClassSig {
        package,
        parts: vec![jdc_core::types::ClassSigPart { name, args: vec![] }],
    }
}

/// Render a type reference for signatures where the printer is not used.
pub fn type_ref_of(desc: &str) -> TypeRef {
    TypeRef::J(desc_type(desc))
}
