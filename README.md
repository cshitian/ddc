# ddc — DEX → Java decompiler in Rust

**English** | [简体中文](README.zh-CN.md)

[![CI](https://github.com/ejfkdev/ddc/actions/workflows/ci.yml/badge.svg)](https://github.com/ejfkdev/ddc/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

`ddc` decompiles Android DEX bytecode back into readable Java, fast enough
for real-world app bundles — and precise enough to query like a database.

```bash
$ ddc weibo.apk -o out/
ddc: wrote 98348 file(s) to out/ in 5.54s
```

| | |
|---|---|
| 226 MB / 20-dex APK (weibo) | 98k classes → **5.4s** |
| 353 MB / 59-dex bundle (Lark/Feishu) | 208k units → **9.2s** |
| a string search across that 353 MB | **0.07s** — no full decompile |

## Highlights

- **Full DEX 035–041 support** — multi-dex APKs, XAPK/APKS/APKM split
  containers, `invoke-polymorphic` / `invoke-custom`; lambda and
  string-concat call sites fold back to real Java (`(a) -> …`, `Cls::name`,
  `a + b`).
- **20+ progressive subcommands** — strings, cross-references, class
  hierarchies, the manifest, resources, per-method decompiles — answers in
  tens of milliseconds, before any full decompile.
- **Real-world hardening** — pathological classes run on monitored threads
  with deadlines instead of hanging the run; panics are contained per
  class.
- **Reproducible output** — no timestamps, so two runs diff cleanly.
- **Bilingual CLI** — messages auto-localize to Chinese from the locale
  (`DDC_LANG=zh|en` overrides; English fallback).
- Built on [`jdc-core`](https://crates.io/crates/jdc-core) — the
  machine-neutral decompiler core shared with
  [jcdc](https://github.com/ejfkdev/jcdc).

## Install

Prebuilt binaries for Linux (x86_64, aarch64), macOS (x86_64, Apple
silicon) and Windows (x86_64) ship with every
[release](https://github.com/ejfkdev/ddc/releases) — raw binaries, no
archives; non-macOS builds are UPX-compressed. Tag a version and CI builds
all five targets with the binary version stamped from the tag.

From source (Rust stable):

```bash
git clone https://github.com/ejfkdev/ddc && cd ddc
cargo build --release        # the profile already sets fat LTO + 1 CGU
./target/release/ddc --help
```

## Usage

```bash
ddc app.apk                          # full decompile → app-out/
ddc app.apk src/                     # dae/pycdc-style positional output
ddc app.apk -c com.example.Foo       # one class to stdout
ddc app.apk -o - | less              # everything to stdout

ddc mainactivity app.apk             # entry point: package + launcher
ddc findrefs app.apk string token    # every const-string "token" site
ddc getmethod app.apk Foo.toString   # one method, all overloads
ddc pkg app.apk --app -o own/        # app's own code only, no androidx
ddc manifest app.apk --component launcher    # (see --help)
```

`ddc --help` prints the full option list, the subcommand menu grouped by
workflow, and worked examples — in your language.

Progressive-analysis quick reference (weibo, 226MB/20dex):

| | | | |
|---|---|---|---|
| `info` **0.11s** | `listclasses` **0.10s** | `manifest` **0.06s** | `mainactivity` **0.02s** |
| `findrefs string` **0.14s** | `findrefs type/method/field` ~0.5s | `strings` **0.04s** | `members` **0.04s** |
| `hierarchy` **0.04s** | `largest` **0.06s** | `disasm` **0.04s** | `res` **0.01s** |
| `getclass` **0.03s** | `getmethod` **0.03s** | `callers` ~0.5s | `pkg` 0.165s |

Full details, output formats and match semantics:
[docs/subcommands.md](docs/subcommands.md)
([中文](docs/zh-CN/subcommands.md)).

## Documentation

| | |
|---|---|
| [Architecture](docs/architecture.md) | the three crates, the lift/structure/emit pipeline, DEX versions, invoke-custom ([中文](docs/zh-CN/architecture.md)) |
| [Subcommands](docs/subcommands.md) | the progressive-analysis reference ([中文](docs/zh-CN/subcommands.md)) |
| [Benchmarks](docs/benchmarks.md) | full-decompile and query timings across six real APKs, methodology, comparison with ASC ([中文](docs/zh-CN/benchmarks.md)) |
| [Performance engineering](docs/optimization.md) | 5min → 5.4s: the six rounds, the measured dead ends, the floor analysis ([中文](docs/zh-CN/optimization.md)) |

## Known limitations

Erased types (DEX carries no Signature); d8-desugared `-$$Lambda$` classes
stay separate files; a handful of R8 monster methods degrade via timeout;
pattern-switch and string-switch render as desugared dispatch chains.
Details: [docs/architecture.md](docs/architecture.md).

## Testing

```bash
cargo test    # 56 tests: decode/end-to-end + CLI + subcommand integration
```

## License

[MIT](LICENSE) © ejfkdev. [`jdc-core`](https://crates.io/crates/jdc-core)
is MIT as well.
