# Performance engineering

[English] | [简体中文](zh-CN/optimization.md)

How ddc got from **5 minutes to 4.6 seconds** on weibo (226MB, 20 dex,
98k classes) — every item below was located by stack sampling or phase
instrumentation, then verified by re-measurement.

## The rounds

| Round | weibo | Key fixes |
|---|---|---|
| baseline | 5min | — |
| 1 | 110s | exponential Pending materialization cap (the 9.8GB memory root cause), exponential traversal, worklist fixpoint, double decode, non-blocking timeouts |
| 2 | 90s | dynamic work queue (P/E core imbalance), single-block fast path, directory caching |
| 3 | 57s | **mimalloc** (system malloc ate half the CPU), signature gate first, merge borrowed sides, try-entry snapshots, cleanup 8→3, **LTO fat + native CPU** |
| 4 (jdc-core) | 24s | structuring algorithm fixes (below) |
| 5 | 19.6s | **stable variable IDs**: `fresh_var` minted a new id per rebuild → out-states never equaled → worklist cascades (30M block rebuilds); `(block, reg) → var_id` reused across rebuilds |
| 6 | **5.6s** | front-end and pipeline (below) |
| 7 | **4.6s** | allocation & I/O round (below) — weixin 16.5s → 10.7s, lark 5.8s → 4.9s, qq 18.0s → 13.6s on the same pass |

## The big fixes, in order of impact

1. **Exponential Pending growth** (memory 9.8GB → 157MB): register Pending
   expressions carried around loops get whole-cloned at merge points every
   fixpoint round — the tree doubles with iterations. Expressions beyond
   96 nodes materialize into local variables in `write()`; the state tree
   is bounded from then on.
2. **Exponential traversal**: `stmt_collect_vars` recursed into itself
   inside the `walk_all` closure, traversing every nesting level twice
   (O(2^depth)) — rewritten as plain single-pass recursion (one class:
   90s → 0.17s).
3. **Full-recompute fixpoint**: the round-based loop deep-cloned and
   deep-compared all register states (Expr trees) every round — replaced
   by a worklist + output version stamps, recomputing only blocks whose
   predecessors changed.
4. **Double decode**: the risk check and the pool each fully decoded all
   145k methods — replaced by an 8-byte code_item header peek.
5. **SipHash counters**: the copy-forward pass's HashMap counting did
   three full-tree walks — fused into one pass with Vec indexing.
6. **Blocking timeouts**: pathological classes decompile on a monitored
   thread (64MB stack) with a **5-second deadline counted from spawn**
   (a 10s deadline made deadline-idling the wall-clock critical path);
   workers register the receiver and move on, the tail reaps in deadline
   order. Threshold calibrated on real load: ordinary R8 methods ≤11k
   insns, the exponential-walk gson adapters ≥24k → the 16k-instruction
   boundary.
7. **Parallel multi-dex inflate+parse** (inflate and header/string/
   annotation decode on the same thread).
8. **Dynamic work queue** (32-class chunks + atomic cursor): static
   equal partitioning tails badly on P/E hybrid cores — small chunks let
   slow cores naturally take fewer.
9. **Single-block fast path**: single-basic-block methods (>50% of R8
   output) have no control flow to structure — skip the structurer,
   converter, and control-flow passes entirely.
10. **Writer thread pool** (bounded MPMC): 98k files × 992MB of writes
    decoupled from decompilation — inline `fs::write` once stalled workers
    64s on APFS metadata ("busy" ≠ CPU). Each writer holds its own mkdir
    cache. Queue bound settled at 1024 slots after two reversals (256
    back-pressured workers in the single-writer era; 1<<20 was absorbed by
    the page cache; 1024 costs no wall time and saves 185MB RSS).
11. **Gated instrumentation** (phase/bucket timings, DOM counters) behind
    `OnceLock`/`AtomicBool` — `env::var` per method was 716k lock+lookups.

### Round 4: jdc-core structuring (all additive, default behavior unchanged)

Once the front-end hotspots were fixed, sampling showed the hotspot had
*migrated* into jdc-core's exception-grouping / scoping machinery — its
sampling weight was ~4× `walk_inner` itself:

1. `group_exceptions_with`: the O(G²) merge loop re-allocated and
   re-sorted `handler_key` for every pair comparison — precompute once,
   maintain incrementally while merging (the 57→23s main contribution).
2. `sub_scope`: cloned the universe twice per call, linear-scanned all
   blocks in `holds_start`, and re-scanned all blocks per span extension
   (O(B·G)) — no clones, a `block_at_start` hash index, `starts_partition`
   binary-searched slices.
3. `expand_orphan_group_tails`: nested `groups × out` any-scans — one
   pass materializes `groups_in_out`; `start_held` full-block scans became
   index probes.
4. `compute_dominators`: per-edge HashSet membership → one dense bitset
   pass; `Printer::into_string`'s `truncate_dead_ends` deep-cloned the
   whole statement tree unconditionally — read-only probe first, clone
   only when a dead end exists.

### Round 6: front-end and pipeline

1. **`Block.ins` slices**: deep-cloning each block's instruction segment
   (equivalent to decoding every method twice) → `DexCfg` owns the insn
   stream, blocks hold `[lo, hi)` indices.
2. **Interned exception keys**: monster classes (gson adapters with
   hundreds of same-handler try ranges) made O(G²) deep compares of
   `Vec<Vec<(u32, Option<String>)>>` dominate — interned to u32 id
   comparisons; results shared between Structurer and Converter (computed
   once per method via `with_precomputed_groups` / `with_precomputed`,
   jcdc's old API unchanged).
3. **`booleanize` quadratic**: `for i in 0..n { walk_all(...) }`
   re-scanned the whole tree per variable — 2000 vars × 15k statements =
   30M visits/method → one pass collecting (any, all_bool).
4. **Dead traversal removal**: `ensure_declared`'s `assigned` set was
   collected and never used (a full-tree walk + HashSet per method) —
   deleted; `params/declared` HashSets → dense `Vec<bool>`.
5. **Fixpoint per-visit cost**: try-entry checks re-scanned all exception
   ranges per visit (including a block_at binary search) + handler catch
   types cloned Strings — precomputed `try_entry_flags` / `handler_types`
   outside the loop (weibo 14.1→10.6s main contribution).
6. **Pass feature gating**: lift sets SB/monitor/cmp flags (`MethodFlags`
   escaping the consumed lifter via `&mut`) — methods without
   StringBuilder skip the whole `fold_string_builders` analysis, without
   monitors skip `fold_synchronized`; `fused_expr_rewrites` does cmp
   residue + null comparison + constant hoisting in one pass (was three).
7. **DexPool borrows**: `children_of`/`outer_of` cloned Vec/Strings per
   class — borrowed slices.
8. **5s monitored-thread deadline**: the one truly-timing-out class's 10s
   deadline was the tail-draining critical path (work finished at 4.3s,
   then 6s of idle waiting); at 5s every other monitored class still
   completes within its deadline.

## Round 7: allocation, hashing, syscalls (5.6s → 4.6s weibo)

Profiled with samply; every item below showed up as a named hotspot
first. Also fixed two correctness bugs found on the way (a released
v0.1.4 one): value-forwarding rewrote ASSIGNMENT TARGETS (`25 = 25;` —
242 occurrences in reqable alone), and phi-commit ordering followed
the hasher's iteration order (output was not byte-stable across runs —
243/5579 files wobbled).

1. **Writer pool**: workers hand finished sources over in ~32-file
   batches (one mutex acquisition per batch, bound counted in FILES);
   `create_new` open replaces the unconditional remove+open per file
   (3 syscalls instead of 4, case-variant semantics preserved by the
   EEXIST fallback — no shard locks needed); the package-directory tree
   is pre-created on a background thread while parsing runs (writers
   pay zero mkdir in the common case). Writers = clamp(cpus/4, 2, 4),
   and the default worker count RESERVES those cores (18+4 threads on
   18 cores slowed both sides).
2. **FxHash everywhere** (jdc-core + ddc-dec): the universe/dominator/
   walk-guard sets and per-method tables hashed usize keys with
   SipHash-1-3 (~5% of worker CPU).
3. **Arc-ified IR payloads**: `JavaType::Object`, `Expr::{Method,Field,
   New}` names, `MethodDescriptor`, catch-type chains and
   `ConstVal::Str` are `Arc<str>`/`Arc` now, backed by per-image
   intern caches (`DexRefCache`: proto → descriptor, type → internal
   name/parsed type, OnceLock slots). `method_ref` went from 6-10
   allocations per invoke instruction (params → `format!` → re-parse!)
   to zero; every downstream IR clone is a refcount bump.
4. **group_exceptions_with**: was the single hottest jdc-core function
   on weixin (11.8% self). Indexed first-pass grouping, handler keys
   computed once (not per pair-comparison), fingerprint-bucketed merge
   loop, binary-search windows for the gap scans (was full exc_range +
   block scans PER PAIR), statement-tree walks hoisted into a
   once-per-method prefix table, handler-protection pairs indexed by
   start pc, and the per-pair TryGroup clones moved behind the cheap
   predicates.
5. **Zero-copy text assembly**: methods render straight into the class
   buffer at their absolute indent (Printer::with_indent +
   with_output) — the intermediate per-method String, the per-line
   re-indent pass and the whole-body `push_str` copy are gone;
   provenance headers write directly (no per-class `format!`s); class
   buffer pre-sized (capped) from the method count.
6. **Borrowed hot data**: Structurer/Converter share the method's
   exception groups and dominators by reference (Cow) instead of three
   deep clones per method; booleanize/infer_types hold `Vec<&TypeRef>`
   and only write changed Local types.
7. **Lock and churn removal**: `DexFile::raw()` (per-class mutex under
   18-way materialize → RwLock + one hoisted snapshot per image in
   `materialize_all`; per-helper call batching), env-var reads behind
   OnceLocks (they ran per method/per identifier), `java_ident`
   returns Cow, mimalloc `MIMALLOC_PURGE_DELAY=1000` (madvise churn
   under bursty per-method IR lifetimes).

Known residual: a handful of deadline-guarded monster methods (weibo's
gson TypeAdapters, ~5 files) can still vary between runs — the
wall-clock walk guard truncates by design; both variants compile.

## Round 8: the quality round (external lab-package feedback)

A reviewer compiled ddc's output of a small hand-made APK against the
real `android.jar` (full javac, not our syntax gate) and got ~100
semantic errors where jadx got 1. Reproduced on a rebuilt lab package,
root-caused and fixed — every item below was a real bug in v0.1.4,
invisible to the syntax-only gate:

1. **Inverted null-compare rewrite** — `obj == 0` replaced the LOCAL
   side with null instead of the const side: every object null check in
   every corpus rendered `null != 0` (4,598 hits in reqable alone).
2. **`children_of` OnceLock double-set** — an empty map was stored
   first, the real index silently discarded: member nested classes were
   neither inlined nor emitted (whole classes missing from output).
3. **`return 0` for `return null`** — const-0 in object contexts
   (return-object / throw / reference args / field stores) now coerces
   to `null` at lift.
4. **Register retyping** — the stable-var registry keyed `(block,
   slot)` and RETYPED vars in place (`byte[] v1 = …; v1 = s(v1,…)` with
   a String). Key is now `(block, slot, type-fingerprint)`: a retyped
   register mints a fresh var.
5. **Static nested classes rendered as inner** (`str.new Report(…)`
   eating the first ctor arg) — DEX from plain d8 carries no nesting
   annotations; the static check now falls back to structural evidence
   (no instance field typed as the outer class), and inline member
   headers gained their `static`.
6. **`super()` rendered `new Object();`** — the ctor receiver
   `Local{var:0}` was not recognized as `this`; normalized at lift.
7. **Scope violations** — a `LocalDef` inside a branch whose var is
   referenced outside now hoists (two-pass pre-order block numbering +
   inside/outside occurrence counts); dead phi-commit residue
   (`printStream = check;`) drops via `drop_dead_locals`; write-only
   vars count as uses in `ensure_declared`.
8. **StringBuilder fold ate the value** — `toString()` on a builder
   whose appends went through an alias register folded to `""`; empty
   chains never fold now.
9. **Double allocation** — inlining a folded `new` at the register's
   final read left the Pending view for the block-exit materialization
   to emit again; final-read inlines now consume the register (raw
   `new` views exempt — the ctor fold still needs them).
10. **`boolean` method returning `int`** — return-position locals of
    boolean methods are booleanize candidates.

Lab package after the round: **0 full-compile errors** on all three
dex variants (v0.1.4: 39 on the same gate). Corpus re-gate: 7 APKs +
alipay/MinisApp ≈ 1.18M files, zero syntax errors, zero decompile
failures; outputs byte-stable across runs (lark/weixin/reqable diff 0).
Cost: ~+10% CPU on large corpora (weibo 4.6→5.0s, weixin 10.7→11.6s;
lark/qq also render their nested members now — output that v0.1.4
silently dropped), lark RSS +200MB (nested-class inlining).

## The floor below 5.6s (if you want to go further)

Total CPU ~65s (user 53 + sys 12) ÷ ~8 effective P-cores ≈ 8.1s
theoretical parallel floor. Bucketed: >100-block monsters ~20s CPU
(jdc-core walk region exploration + per-scope dominator recomputation),
6–20-block methods ~13s, printing ~5s, disk sys ~12s (98k files of APFS
metadata; writer threads already overlap decompilation). Reaching 3s
needs Expr arena allocation, sub-domain dominator indexing, and an
algorithmic rewrite of the monster-class walk.

## Measured dead ends

- Walk visit budget (Goto fallback retriggers expansion → 157s, worse) —
  the patch is kept but dormant.
- SESE paths (complete the hang-class walks but 28.7s/class — slower).
- Per-block initial-copy budget scaling (no effect).
- **mmap** for APK reads (28ms page-cache hits; no headroom).
- **SIMD** (the bottleneck is graph-algorithm heap allocation, not data
  throughput; LEB128/MUTF-8 are 0.8s of pool build — no target).
- Block chunk 256→32 (CPU went up; no wall gain).
- Threads >16 (E-core backlash: 68 user vs 58).
- Writer queue bound: two reversals — re-test when the writer
  architecture changes.
