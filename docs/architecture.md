# Architecture

[English] | [简体中文](zh-CN/architecture.md)

`ddc` is a three-crate workspace. The machine-specific front-end lives in
`ddc-dex`/`ddc-dec`; the machine-neutral core (CFG structuring, statement
conversion, Java emission) is [`jdc-core`](https://crates.io/crates/jdc-core)
— the same core [jcdc](https://github.com/ejfkdev/jcdc) drives for JVM
classfiles:

```text
ddc-dex (machine-specific)               jdc-core (machine-neutral)
────────────────────────                 ─────────────────────────
DEX parsing (header/ids/class_def/code)  cfg::Cfg             blocks + edges
Dalvik decode (all opcodes + payloads)   ir::BlockResult      stmts + term
register→IR lifting (expr/phi)     ───►  structure/sese       region tree
machine idioms (ctor fold, SB, …)        convert::Converter   Stmt tree
refinement passes (copy fwd, types)       emit::Printer        Java source
```

## crates/ddc-dex — DEX container and instruction decoding

- `DexFile`: header / string (MUTF-8) / type / proto / field / method /
  class_def — lazy, fault-tolerant parsing (out-of-range indices return
  sentinels instead of failing).
- `insn`: every Dalvik opcode (0x00–0xff, including the 038 additions
  `invoke-polymorphic` / `invoke-custom` / method handles) and the three
  payload pseudo-instructions; all instructions carry absolute jump
  targets. The nibble layouts follow the two families `B|A|op`
  (12x/11n/22c/22t/22s) and `A|G|op` (35c).
- `code`: `code_item` + try tables + `encoded_catch_handler` (both
  handler_off offset conventions).
- `annotations`: encoded_value / nested-class annotations / static field
  initial values.

## crates/ddc-dec — decompiler front-end

- **lift.rs**: the register file is modeled as a per-register *value view*:
  `Live(v)` (a local, statement already emitted), `Pending(e)` (a pure
  expression, stored for delayed nesting), `PendingCall(e)` (a call result
  consumed exactly once). Non-pure views materialize at block exits; only
  pure values, locals and open `new` views propagate across blocks.
  Constructor folding (`new-instance` + `invoke-direct <init>`), d8's
  statement-chained `StringBuilder.append` with discarded results, and
  `fill-array-data` filling are handled here.
- **method.rs**: fixpoint iteration + merged phis (diverging registers emit
  assignments ordered by write-pc; values referencing sibling phis are
  snapshotted into temporaries so register rotation `a=b; b=a%b` is
  expressed correctly). When the entry is a loop head (d8 back-edges to
  pc 0) the entry-side phi initializes from a `LocalDef` at the top of the
  body; exception-handler entries approximate with the try-entry state.
- **passes.rs**: catch-parameter binding, ternary folding (`if/else`
  assigning the same variable), `StringBuilder` chains → `+`
  concatenation (statement-level append absorption), `synchronized`
  recovery (d8 monitor patterns), single-use temporary copy-forward
  (pure values anywhere, impure only adjacent; multi-assignment references
  guard against stale captures), evidence-driven type inference (call-site
  parameter/return/field/receiver), booleanization and null comparisons,
  declaration cleanup.
- **ctx.rs**: the `jdc_core::Ctx` implementation for DEX (nested classes
  from dalvik annotations + the `$` heuristic; type hierarchy walks;
  constructor arity queries).
- **classdec.rs**: class headers / fields (static initializers) / method
  signatures / nested member-class inline rendering; anonymous / local /
  `-$$Lambda$` classes each get their own file.

## crates/ddc-cli — command line

Ships a minimal ZIP reader (stored + deflate); APK dexes merge in numeric
`classes.dex, classes2.dex, …` order (first definition wins for duplicate
classes). AXML decoding (string pools UTF-16/UTF-8, typedValue rendering)
lives in `axml.rs`; manifest facts and resource entry extraction in
`manifest.rs`; the progressive browse subcommands in `browse.rs`;
bilingual message selection in `lang.rs`.

## DEX version support

All standard versions: **035, 037, 038, 039, 040, 041** (magic validated;
unknown versions rejected — 036 was an unofficial odex-era marker that ART
also rejects). The container layout is identical across versions; the
differences are feature signals:

- **035**: the base format (the vast majority of APKs)
- **037+**: `invoke-polymorphic` (45cc/4rcc), `invoke-custom` (35c/3rc),
  `const-method-handle`, `const-method-type`
- **038/039**: d8 marks these for min-api ≥ 26 / 28 (default methods /
  invokedynamic without desugaring signals)
- **040/041**: ART internal markers (verification state); container
  unchanged

## invoke-custom (DEX 037+, `d8 --no-desugaring` output)

- The `call_site_id` (map 0x0007) and `method_handle` (map 0x0008, `HHHH`
  layout) tables are parsed from the map_list.
- `LambdaMetafactory` sites render as real Java: non-capturing lambdas as
  `(a0) -> Cls.lambda$run$0(a0)`, method references as `Cls::name` (SAM
  parameters taken from the instantiated-type linkage arguments).
- `StringConcatFactory` sites parse the recipe and fold back into `+`
  concatenation expressions.
- `const-method-handle` → `Cls::name` literals.
