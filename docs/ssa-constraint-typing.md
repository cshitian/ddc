# SSA Constraint Typing — Design

Status: proposed (design-doc-first per project convention)
Scope: ddc-dec lift/type layer + jdc-core converter hand-off
Target families (whole-directory sweep, 41 APKs / 4.17M files / 377k errors):

| family | count | confirmed conflation shapes |
|---|---|---|
| incompatible types (all pairs) | ~50k | int↔String, Object[]↔int, T↔T unrelated |
| cannot-find 变量/方法 (non-phantom part) | ~30k | receiver bound to wrong generation (`Unit.INSTANCE.n7()`) |
| binop operand errors (`\|`, `!=`, `==`) | ~12k | bool/int/reference mixed operands |
| deref primitive (无法取消引用int/boolean/long) | ~6k | field/method access on primitive-typed local |
| final-assign | ~5k | vt-typing cascade downstream |

All five trace to ONE root: **a rendered local's type (or identity) does not
match the value flowing at a given program point** — register reuse across
types, phi merges of unrelated same-typed values, and call-site descriptors
diverging from the receiver's inferred type.

## 1. Why the current machinery falls short

Typing today is a stack of local heuristics, each fixing one projection of
the problem:

1. `lift.rs fresh_var` — vars keyed `(block, slot, type_key)`: register
   reuse with a DIFFERENT instruction-local type mints distinct vars.
   Correct as far as it goes, but the type key is derived per-instruction
   (move-result desc, const shape) with no cross-block consistency.
2. Block merges materialize register state (OutState/write_pc), then the
   jdc-core converter/structurer folds branch values into rendered locals
   (value views, phi snapshots). A merge of two unrelated values with the
   same type key renders as ONE local — conflation born here.
3. `passes::infer_types` — per-var evidence voting (strong def facts vs
   weak use facts) over the FINAL tree. A vote cannot express "int on
   path A, int[] on path B" — it picks one and the other path breaks.
4. `split_generations` / `booleanize` — post-hoc splits when an assign
   type contradicts the declared type (bool/num focus). Splits are
   triggered by syntactic mismatch, not by flow facts, so same-type
   conflations (String vs String with different meanings are fine, but
   `Integer` vs `int[]` under one rendered name) and receiver-vs-desc
   divergence slip through.

Confirmed field evidence (all bytecode-verified this round):

- **Receiver divergence** (weibo `dq`): `boolean v = this.c()` where the
  call's dex desc belongs to another class — the receiver register was
  conflated with `this`; ~1.5k weibo `int无法转换为boolean`.
- **Cross-path phi of different types** (weixin `ui0/d1`): one rendered
  `Integer num6` read as `num6[i]` — the register held `int[]` on the
  path that feeds the array reads, `Integer` on the path that feeds the
  boxing; 187 errors in one file.
- **Coroutine capture conflation** (lark fileupload `f`):
  `kotlin.Unit.INSTANCE.n7(null)` — a state-machine `L$0` field carries
  different captures across resumes; forward propagation pushed the
  `Unit.INSTANCE` store into a read whose true value was the
  `kotlinx.coroutines.sync.a` capture.
- **Same-name multi-class methods**: `int c()` and `String c()` on
  different nested classes; the receiver var decides which — a
  mis-typed receiver silently re-targets the call.

The twice-falsified "widening" route (widen the var type + cast at use,
+34k battery) proved the direction: **the fix must SPLIT values along
paths, never widen a shared var.**

## 2. Proposal: constraint typing over the lifted CFG

The DEX instruction stream is a complete type-fact source: every invoke
carries its owner+proto, every field access its owner+desc, every const
its exact type, checkcast/new/const-class are exact. The verifier already
guaranteed consistency. We re-derive that consistency as a constraint
system over SSA values and solve it BEFORE structuring destroys the
control flow.

### 2.1 SSA values

A **value** = (register slot, defining instruction pc) — exactly the
granularity `fresh_var`'s (block, slot, ty_key) approximates. Phi values
at merge blocks are first-class: value(slot, merge-block) with edges from
each predecessor's exit value for that slot.

The lift already produces block-scoped vars; the new piece is an explicit
**value graph** (defs, uses, phi edges) retained alongside the lifted
statements until structuring.

### 2.2 Constraints (per InsnKind)

| instruction | constraints |
|---|---|
| `const v, #k` | `type(v) = Int/Long/Float/Double` (exact) |
| `const-string v` | `type(v) = String` |
| `new-instance v, C` / `new-array v, T[]` | `type(v) = C` / `T[]` |
| `move vA, vB` | `type(vA) = type(vB)` (equality edge) |
| `checkcast v, C` | `type(v) = C` (exact, authoritative) |
| `invoke {vR}, vA, args → vRes` | `type(vR) <: owner`; `type(arg_i) <: formal_i`; `type(vRes) = ret` |
| `iget/iput vA, vR, F:T` | `type(vR) <: owner(F)`; `type(vA) = T` (iput: `<: T` with boxing bridge tolerance) |
| `aget/asize/astore` | array vs element typing |
| arithmetic / cmp | numeric-category equality among operands+result |
| `if-*` | operand categories |
| `instanceof → v` | `type(v) = Boolean` |
| phi merge | `type(phi) = join(type(pred_i))` over the subtype lattice |
| `return v` | `type(v) <: declared_ret` |

`<:` resolves through pool (app classes, full hierarchy) + fwdb
(framework, including removed-API entries) — both already embedded.

### 2.3 Solver

Three layers, all per-method (no cross-method graph):

1. **Equality unification** — union-find over values connected by `move`
   and same-def edges. Near-linear.
2. **Subtype propagation** — worklist over `<:` constraints; each union
   class accumulates its lower bounds (observed exact types from descs)
   and upper bounds (formal/owner/field expectations). Resolve to the
   MOST SPECIFIC consistent type: meet of uppers ⊒ join of lowers.
3. **Conflict = SPLIT, never widen** — when a union class accumulates
   incompatible exact facts (Integer vs int[]; String vs boolean), the
   class is a conflation site: split it along the CFG dominator frontier
   (the phi edges whose inputs carry the different facts) into distinct
   rendered vars, each keeping its own solved type. This is the
   `split_generations` idea driven by solved flow facts instead of
   syntactic mismatch.

Determinism: worklist seeded in (block, pc) order; union-find keyed by
value ids — same output per run (project invariant).

Cost: O(insns · α) for unification + bounded worklist (each class's bound
set changes monotonically); per-method, single-threaded within the
existing per-method worker. Budget: ≤ +10% decompile wall (weixin ≤ 24s).

### 2.4 Use-site residue

Where a phi join is legitimately wide (Object) but a USE constrains
narrower (field owner, formal, receiver), emit a use-site cast to the
use constraint — the solved type makes this evidence-based, replacing
today's heuristic rescuers (`rescue_primitive_receivers`,
`insert_object_narrowing_casts`) which guess by slot/max-id and caused
the str11 hijack family before their guards.

## 3. Integration phases (each gated: battery + affected sweep corpora +
determinism + clippy/tests; net-numbers rule; A/B revert criteria)

- **Phase 0 — census (no behavior change)**: build the value graph +
  constraints; count conflation sites (union classes with incompatible
  exact facts) and desc-vs-receiver divergences per corpus; emit under
  `DDC_SSA_REPORT`. Establishes the addressable population before any
  render change.
- **Phase 1 — receiver/desc authority**: solved types override vt for
  CALL RECEIVERS where desc-owner and inferred type diverge (dq family).
  Narrowest render-visible slice; re-targets `this.c()` to the right
  generation or splits it.
- **Phase 2 — phi splits**: split conflated union classes into per-path
  rendered vars (ui0/d1 Integer-vs-int[] family). Touches the converter
  hand-off (jdc-core): split vars ride the existing generation naming
  (`vN_gK`) and `split_generations` rendering rails.
- **Phase 3 — coroutine capture guard**: state-machine `L$N` field reads
  are marked capture-conflated (different value per resume); forward
  propagation across a suspend boundary is cut (lark `Unit.INSTANCE.n7`
  family).
- **Phase 4 — evidence-based use-site casts**: replace the heuristic
  rescuer gates with solved constraints; delete the max-id fallbacks.
- **Phase 5 — retire votes**: `infer_types` evidence voting demoted to
  fallback for values the constraint system could not resolve (should be
  ~0 for verified dex).

## 4. Risk register (project history)

- Type-family fixes must be validated with-classpath on ALL corpora
  (no-cp metrics blind to unresolvable-pool-class casts) — standing rule.
- Parse errors mask semantic errors: any error-count drop must be checked
  against the parse-error count.
- Net numbers over family counts: fixing one family unmasks the next.
- Renames/registries are NOT touched by this design (no blast radius on
  the name-resolution layer).
- The widening route is falsified (twice): every phase splits or retypes
  per-path; none widens a shared var.
