# ddc — DEX → Java decompiler in Rust

**English** | [简体中文](README.zh-CN.md)

[![CI](https://github.com/ejfkdev/ddc/actions/workflows/ci.yml/badge.svg)](https://github.com/ejfkdev/ddc/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

`ddc` decompiles Android DEX bytecode back into readable Java, fast enough to
run against real-world app bundles: a 226 MB / 20-dex APK (weibo, 98k classes)
lands on disk in **~5.5 s**; a 353 MB / 59-dex bundle (Lark/Feishu) in **~9 s**.

It reuses [`jdc-core`](https://crates.io/crates/jdc-core) — a machine-neutral
decompiler core (CFG structuring, statement conversion, Java emission) — and
implements the Dalvik register-machine front-end for it, mirroring the
architecture of [jcdc](https://github.com/ejfkdev/jcdc) (the JVM classfile
front-end):

```text
ddc-dex (machine-specific)               jdc-core (machine-neutral)
────────────────────────                 ─────────────────────────
DEX parsing (header/ids/class_def/code)  cfg::Cfg             blocks + edges
Dalvik decode (all opcodes + payloads)   ir::BlockResult      stmts + term
register→IR lifting (expr/phi)     ───►  structure/sese       region tree
machine idioms (ctor fold, SB, …)        convert::Converter   Stmt tree
refinement passes (copy fwd, types)       emit::Printer        Java source
```

## Highlights

- **Full DEX version support** — 035 through 041, including
  `invoke-polymorphic` / `invoke-custom` / method handles; lambda and
  string-concat call sites are folded back to real Java (`(a) -> …`,
  `Cls::name`, `a + b`).
- **Real-world speed** — parallel inflate+parse across dex images, a bounded
  MPMC write pipeline, mimalloc, fat LTO; pathological classes are handled on
  monitored threads with deadlines instead of hanging the run.
- **Progressive analysis** — 20+ subcommands that query the artifact like a
  database (strings, cross-references, hierarchies, the manifest, resources)
  in tens of milliseconds, before you ever pay for a full decompile.
- **Reproducible output** — no timestamps; deterministic content (modulo
  std HashMap seed for a few variable IDs), so two runs diff cleanly.
- **Containers** — `.dex`, `.apk`/`.jar`/`.zip`, XAPK/APKS/APKM split bundles
  (base APK first, per-APK `--dex` filtering), and directories of any of
  those, merged into one class pool.

## Install

Prebuilt binaries for Linux (x86_64, aarch64), macOS (x86_64, Apple silicon)
and Windows (x86_64) are attached to each
[release](https://github.com/ejfkdev/ddc/releases) — raw binaries, no
archives; the non-macOS ones are UPX-compressed.

Or build from source (Rust 1.7x, stable):

```bash
git clone https://github.com/ejfkdev/ddc
cd ddc
cargo build --release        # release profile already sets fat LTO + 1 CGU
./target/release/ddc --help
```

## Quick start

```bash
ddc app.apk                          # → app-out/ next to the apk
ddc app.apk src/                     # dae/pycdc-style positional output
ddc app.apk -o -                     # everything to stdout
ddc app.apk -c com.example.Foo       # one class (stdout)
ddc base.apk patch.dex -o merged/    # split inputs, one pool

ddc mainactivity app.apk             # entry point: package + launcher
ddc findrefs app.apk string token    # every const-string "token" site
ddc getclass app.apk com.example.Foo # that one class, +nested
ddc pkg app.apk --app -o own/        # app's own code only, no androidx
```

Input formats: `.dex` (035–041), `.apk`/`.jar`/`.zip` (all `classes*.dex`
entries, numeric order), `.xapk`/`.apks`/`.apkm` (container of APKs — base
first, labels like `container!base.apk!classes.dex`, `--dex base` /
`--dex config.arm64` filter by inner APK), and directories (scanned
recursively). Multiple inputs merge into one pool with duplicate classes
deduplicated.

Output is one of: **a directory** (`.java` files laid out by package), **a
single `.java` file** (`-c`), or **stdout** (`-`). Without `-o`, files land in
`<input-name>-out/`; `-c` defaults to stdout.

| Option | Meaning |
|---|---|
| `-o, --output <path>` | directory / `file.java` (single class) / `-` (stdout) |
| `-c, --class FQCN` | decompile one class (default stdout) |
| `-l, --list` | list class names, exit |
| `-t, --threads <n>` | workers (default: CPU count; stdout forces 1 for pool order) |
| `--no-comments` | omit the provenance header |
| `-v, --verbose` | per-dex stats and slow classes on stderr |
| `-h` / `-V` | help / version (`--opt=value` accepted) |

Exit codes: `0` ok; `1` some classes failed (e.g. pathological-CFG timeout);
`2` usage error (full help printed).

Every `.java` carries a provenance header (unless `--no-comments`):

```java
// Decompiled by https://github.com/ejfkdev/ddc 1.2.3
// From: app!classes3.dex (DEX 038)
// Source file: Foo.java
```

`From:` is the fastest clue for which image a class lives in (jadx's
`loaded from:` pattern). A one-line summary goes to stderr when the run
finishes: `ddc: wrote 98348 file(s) to out/, 1 failed in 5.54s`.

## Progressive analysis (subcommands)

Query the artifact as a database — metadata loads only inflate + parse the
dex header tables (weibo's 20 images, in parallel, ~0.35 s); scans never
enter the lift/structure/render pipeline. Times below are from the author's
machine (Apple Silicon) against weibo (226 MB, 20 dex) unless noted:

| Command | What it does | Time |
|---|---|---|
| `ddc manifest app.apk [--component C]` | AndroidManifest.xml → text XML; `--component launcher\|activity\|service\|…` filters | **0.06s** |
| `ddc info app.apk` | per-image dex version/class/method/field/string counts | **0.11s** |
| `ddc listclasses app.apk [pattern]` | class names, optional fuzzy filter | **0.10s** |
| `ddc getclass app.apk FQCN [-o f]` | one class (+nested), targeted decompile | **0.03s** |
| `ddc findrefs app.apk string TEXT` | every string-literal reference (const-string scan) | **0.14s** |
| `ddc findrefs app.apk type\|method\|field …` | type/new-instance, call sites, field accesses | ~0.5s |
| `ddc strings app.apk [-f TEXT] [--with-locations]` | string table; map const-string hits to owner methods | **0.04s** |
| `ddc members app.apk [NAME] [--class FQCN]` | method/field name search | **0.04s** |
| `ddc hierarchy app.apk FQCN` | lineage: extends/implements + subclasses/implementors | **0.04s** |
| `ddc largest app.apk [-n N]` | top-N methods by instruction count | **0.06s** |
| `ddc disasm app.apk FQCN[.method]` | raw bytecode of a class/method (opcode + pc) | **0.04s** |
| `ddc callers app.apk NAME [FQCN]` | who invokes method NAME | ~0.5s |
| `ddc getmethod app.apk FQCN.method` | decompile ONE method (all overloads, sliced) | **0.03s** |
| `ddc pkg app.apk com.example.foo` | whole-package decompile; `--app` takes the package from the manifest | 0.165s (Telegram tgnet, 1561 classes) |
| `ddc mainactivity app.apk` | package + MAIN/LAUNCHER activity from the manifest, verified in the dex | **0.02s** |
| `ddc res app.apk [entry] [-o FILE]` | list archive entries (XAPK inner APKs too); dump one — binary XML decoded, text as-is, binary via `-o` | **0.01s** |
| (full run, for contrast) `ddc app.apk -o out/` | all 98,348 classes | 5.45s / 1.28GB |

`findrefs` output is columnar (header first, `info`-style; the class is its
own column, no boundary guessing). **One row per method**: multiple hits in
the same method aggregate into the refs column (`; `-separated, deduped);
the kind column is the first hit's instruction:

```
dex         kind          class method refs
hello       const-string  Greeter greet()Ljava/lang/String;  "hi "
classes50.dex  const-string  bz7/c d(...)Ljava/lang/String;  "both_feishu_doubao"; "only_feishu"
```

Match semantics: string/type/names are case-insensitive substrings;
`--class` defaults to exact (dots/slashes/descriptor forms all normalize),
`--fuzzy-class` widens it to substring. One thread per image; zero hits
return instantly.

**Finding which dex holds a class**: `--dex NAME` (repeatable, entry-name
substring) narrows the range before parsing — `getclass --dex classes20`
parses exactly one image (0.09 s on weibo). Ambiguous class names get a
warning listing the images and the `--dex` hint; a bad `--dex` lists all
valid entry names. stdout mode is completely clean (silent stderr); timing
prints only with `-o`. The AXML decoder lives in `ddc-cli/src/axml.rs`
(UTF-16/UTF-8 string pools, typedValue rendering); it also accepts bare
`.axml` files.

### vs. ASC (same machine, alternating 3-round medians, `bench/`)

Five real APKs (62–353 MB), progressive queries, stdout discarded;
correctness cross-checked: 107/107 hits coincide:

| Query | ddc | ASC | Ratio |
|---|---|---|---|
| findrefs string (lark 353MB) | **0.32s** | 0.61s | 1.9× |
| findrefs string (weixin 268MB) | **0.22s** | 0.52s | 2.4× |
| findrefs string (weibo 226MB) | **0.19s** | 0.44s | 2.3× |
| findrefs type/method (all five) | **0.09–0.31s** | 0.29–0.66s | 2–3× |
| getclass (lark/weixin/weibo) | 0.18–0.42s | **0.10–0.12s** | ASC wins |
| getclass (Telegram, big class) | **0.05s** | 0.11s | ddc wins |
| findrefs memory (lark) | ~820MB | ~170MB | ASC leaner |

The getclass split: ASC bit-stream-probes the zip to inflate only the
target dex (a lower floor on huge multi-dex APKs); ddc parses all image
headers (~0.2 s floor) then materializes lazily — it overtakes when the
class itself is expensive, loses to the floor when it isn't. On findrefs
scan domains ddc is uniformly faster (pipeline: parse waves → bounded
channel → scan threads consume-and-drop; `Arc`-shared APK bytes eliminate
compression copies).

## Benchmarks (full decompile)

Author's machine (Apple Silicon, 6P+12E), median of runs:

| APK | Classes | Result | Time | Peak RSS |
|---|---|---|---|---|
| reqable 34MB | 8,201 | 5,579/5,579 units, 0 failed | **0.21s** | 124MB |
| weibo 226MB, 20 dex | 145,492 | 98,348/98,349 (1 pathological gson class times out) | **5.4s** | 1.2GB |
| weixin 268MB | ~250k | 207,338 units | **9.0s** | 1.3GB |
| lark/Feishu 353MB, 59 dex | 567k | 208,702 units | **9.2s** | 2.2GB |
| WhatsApp 139MB | 42,273 units | | **7.5s** | 1.2GB |
| Telegram 62MB | 19,282 | 19,282/19,282 | **7.6s** | 975MB |

Performance notes (every item located by stack sampling, details in
`README.zh-CN.md`):

1. **Exponential Pending growth** (the 9.8 GB→157 MB memory fix): register
   Pending expressions carried around loops are cloned whole at merge points
   each fixpoint round — expressions beyond 96 nodes materialize into locals,
   bounding the state tree.
2. **Exponential traversal**: `stmt_collect_vars` recursing inside
   `walk_all`'s closure doubled traversal per nesting level (O(2^depth)) —
   single-pass rewrite (one class: 90s → 0.17s).
3. **Worklist fixpoint** with output version stamps instead of
   deep-clone-and-compare every round.
4. **Double decode eliminated**: risk check + pooling each fully decoded
   145k methods — now an 8-byte code_item header peek.
5. **Timeouts off the critical path**: pathological classes decompile on a
   monitored 64 MB-stack thread with a 5 s deadline; workers register and
   move on (reaped at the tail, total cost ≤ one deadline).
6. **Dynamic work queue** (32-class chunks + atomic cursor): static
   partitioning tails badly on P/E hybrid cores.
7. **Single-block fast path**: >50% of R8 methods have one basic block —
   skip structuring/conversion/control-flow entirely.
8. **Writer thread pool** (bounded MPMC): 98k files × 992 MB of writes
   decoupled from decompilation — inline `fs::write` once stalled workers
   64 s on APFS metadata.
9. Instrumentation (phase/bucket timing) behind `OnceLock`/`AtomicBool`
   gates — `env::var` per method was 716k lock+lookups.

## Known limitations

- **Generics**: DEX carries no Signature attribute; output is erased types.
- **Lambdas**: d8-desugared `-$$Lambda$` classes stay separate files
  (not inlined); native invoke-custom sites are rendered properly.
- **Pathological CFGs**: a handful of R8-generated methods (weibo's 4 gson
  TypeAdapters) trip the structurer's exponential walk and degrade via
  timeout.
- **Pattern-switch**: d8 desugars to if-chains; not restored to
  `switch`-pattern-matching. String switches appear as hashCode dispatch.
- `append` inside loops is not folded into concatenation expressions
  (repeat semantics can't be expressed); loop-`accumulate` patterns keep
  d8's re-evaluated `length()` calls.

## Testing

```bash
cargo test    # 55 tests: decode/end-to-end + CLI + subcommand integration
```

End-to-end fixtures (real d8-built `tests/fixtures/hello.dex` — asserts
`return "hi " + this.name;` concat folding and
`new Greeter("world").greet()` constructor nesting), shape regressions for
register-machine copy-forward, CLI integration (positional-ambiguity rules,
three output modes, directory inputs, multi-input dedup, exit codes 0/1/2,
provenance headers), and the subcommand suite (real AXML fixture for
manifest decoding, all query kinds, XAPK containers, resource dumps).

## License

[MIT](LICENSE) © ejfkdev. The vendored dependency
[`jdc-core`](https://crates.io/crates/jdc-core) is MIT as well.
