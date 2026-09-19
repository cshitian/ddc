#[test]
fn forward_boxedmath_shape() {
    use ddc_dec::passes::forward_single_use;
    use jdc_core::ir::build::BlockResult;
    use jdc_core::ir::expr::{Expr, TypeRef};
    use jdc_core::ir::stmt::Stmt;
    use jdc_core::types::{JavaType, MethodDescriptor};
    use jdc_core::var::VarTable;

    let int = |v: u32| Expr::Local {
        var: v,
        ty: TypeRef::J(JavaType::Int),
    };
    let mk_call = |owner: u32| Expr::Method {
        owner: Some(Box::new(int(owner))),
        cls: "java/lang/Integer".into(),
        name: "intValue".into(),
        desc: MethodDescriptor {
            args: vec![],
            ret: JavaType::Int,
        },
        args: vec![],
        is_static: false,
        is_interface: false,
        is_special: false,
        is_super: false,
        is_dynamic: false,
        type_args: vec![],
    };
    let max = Expr::Method {
        owner: None,
        cls: "java/lang/Math".into(),
        name: "max".into(),
        desc: MethodDescriptor {
            args: vec![JavaType::Int, JavaType::Int],
            ret: JavaType::Int,
        },
        args: vec![int(4), int(5)],
        is_static: true,
        is_interface: false,
        is_special: false,
        is_super: false,
        is_dynamic: false,
        type_args: vec![],
    };
    let ret = Expr::Bin {
        op: jdc_core::ir::expr::BinOp::Add,
        l: Box::new(Expr::Bin {
            op: jdc_core::ir::expr::BinOp::Add,
            l: Box::new(int(2)),
            r: Box::new(int(3)),
            ty: Some(TypeRef::J(JavaType::Int)),
        }),
        r: Box::new(int(6)),
        ty: Some(TypeRef::J(JavaType::Int)),
    };
    let mut body = Stmt::Block(vec![
        Stmt::LocalDef {
            var: 2,
            init: Some(mk_call(0)),
            is_final: false,
            force_type: true,
        },
        Stmt::LocalDef {
            var: 3,
            init: Some(mk_call(1)),
            is_final: false,
            force_type: true,
        },
        Stmt::LocalDef {
            var: 4,
            init: Some(mk_call(0)),
            is_final: false,
            force_type: true,
        },
        Stmt::LocalDef {
            var: 5,
            init: Some(mk_call(1)),
            is_final: false,
            force_type: true,
        },
        Stmt::LocalDef {
            var: 6,
            init: Some(max),
            is_final: false,
            force_type: true,
        },
        Stmt::Return(Some(ret)),
    ]);
    let mut vt = VarTable::default();
    for (i, ty) in [
        (0u32, JavaType::Object("java/lang/Integer".into())),
        (1, JavaType::Object("java/lang/Integer".into())),
    ] {
        let id = vt.vars.len() as u32;
        vt.vars.push(jdc_core::var::VarInfo {
            id,
            slot: i as u16,
            name: format!("p{}", i),
            ty: TypeRef::J(ty),
            is_param: true,
            range_start: 0,
            range_end: u16::MAX,
            synthetic_name: false,
        });
    }
    forward_single_use(&mut body, &vt);

    let text = format!("{:?}", body);
    assert!(!text.contains("var: 4"), "v4 survived: {}", text);
    assert!(!text.contains("var: 5"), "v5 survived: {}", text);
    let _ = BlockResult {
        stmts: vec![],
        out_stack: vec![],
        term: jdc_core::ir::build::Term::Goto,
    };
}

#[test]
fn forward_cycle_terminates() {
    // A def-reference cycle (loop-carried register rotation reaching the
    // pass as two mutually-referencing single-assign/single-read locals).
    // The frozen `vals` map replaces each cycle Local with the OTHER's
    // definition, whose clone re-introduces this Local again: deep_rewrite
    // grows the tree one layer per level and never terminates. weixin's
    // com.tencent.mm.plugin.appbrand.widget.input.b4 died this way —
    // ~300k recursion frames exhausting a 64MB worker stack.
    use ddc_dec::passes::forward_single_use;
    use jdc_core::ir::expr::{BinOp, Expr, TypeRef};
    use jdc_core::ir::stmt::Stmt;
    use jdc_core::types::JavaType;
    use jdc_core::var::VarTable;

    let int = |v: u32| Expr::Local {
        var: v,
        ty: TypeRef::J(JavaType::Int),
    };
    let mut body = Stmt::Block(vec![
        Stmt::LocalDef {
            var: 2,
            init: Some(Expr::Bin {
                op: BinOp::Add,
                l: Box::new(int(3)),
                r: Box::new(Expr::Const(jdc_core::ir::expr::ConstVal::Int(1))),
                ty: Some(TypeRef::J(JavaType::Int)),
            }),
            is_final: false,
            force_type: true,
        },
        Stmt::LocalDef {
            var: 3,
            init: Some(Expr::Bin {
                op: BinOp::Mul,
                l: Box::new(int(2)),
                r: Box::new(Expr::Const(jdc_core::ir::expr::ConstVal::Int(2))),
                ty: Some(TypeRef::J(JavaType::Int)),
            }),
            is_final: false,
            force_type: true,
        },
    ]);
    let mut vt = VarTable::default();
    forward_single_use(&mut body, &vt);
    // The cycle must survive UN-inlined (both defs stay, no growth).
    let text = format!("{:?}", body);
    assert!(text.contains("var: 2") && text.contains("var: 3"), "cycle defs lost: {text}");
}
