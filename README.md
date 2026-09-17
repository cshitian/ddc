# ddc — DEX → Java decompiler in Rust

**English** | [简体中文](README.zh-CN.md)

[![CI](https://github.com/ejfkdev/ddc/actions/workflows/ci.yml/badge.svg)](https://github.com/ejfkdev/ddc/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

`ddc` decompiles Android DEX bytecode back into readable Java, fast enough
for real-world app bundles — and precise enough to query like a database.

```bash
$ ddc weibo.apk -o out/
ddc: wrote 98348 file(s) to out/ in 6.13s
```

| | |
|---|---|
| 398 MB / 59-dex bundle (Lark/Feishu) | 208k units → **6.1s** |
| 374 MB APK (QQ) | the heavyweight → **17.9s** |
| a string search across that 398 MB | **0.04s** — no full decompile |

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

## Performance

Seven real-world APKs, release build, 3-run averages of wall time; peak
RSS via `/usr/bin/time -l`. Machine: Apple Silicon (6P+12E).

| APK | Size | Full decompile | Peak RSS |
|---|---|---|---|
| reqable | 34 MB | **0.27s** | 147 MB |
| Telegram | 62 MB | **8.09s** | 1016 MB |
| WhatsApp | 139 MB | **8.67s** | 1197 MB |
| weibo | 226 MB | **6.13s** | 1238 MB |
| weixin | 268 MB | **10.15s** | 1413 MB |
| lark | 398 MB | **6.08s** | 1580 MB |
| qq | 374 MB | **17.85s** | 2330 MB |

Every query subcommand on the same seven APKs (cells: wall time / peak
RSS). Queries: `strings -f <package> --with-locations`;
`findrefs string <package>`; `findrefs method onCreate`;
`hierarchy`/`disasm`/`getclass` use each app's launcher class
(Telegram's `LaunchActivity` is an exceptionally large class):

| Command | reqable | Telegram | WhatsApp | weibo | weixin | lark | qq |
|---|---|---|---|---|---|---|---|
| `info` | 0.01s / 24MB | 0.03s / 89MB | 0.04s / 268MB | 0.07s / 510MB | 0.07s / 510MB | 0.07s / 786MB | 0.14s / 1146MB |
| `listclasses` | 0.02s / 17MB | 0.04s / 82MB | 0.05s / 85MB | 0.12s / 372MB | 0.15s / 424MB | 0.16s / 278MB | 0.23s / 366MB |
| `manifest` | 0.00s / 4MB | 0.00s / 10MB | 0.00s / 17MB | 0.01s / 40MB | 0.00s / 28MB | 0.00s / 25MB | 0.00s / 44MB |
| `mainactivity` | 0.01s / 21MB | 0.03s / 85MB | 0.05s / 220MB | 0.08s / 357MB | 0.08s / 386MB | 0.11s / 436MB | 0.17s / 540MB |
| `res` | 0.00s / 4MB | 0.00s / 11MB | 0.01s / 19MB | 0.02s / 58MB | 0.01s / 29MB | 0.01s / 28MB | 0.02s / 50MB |
| `largest` | 0.02s / 28MB | 0.05s / 85MB | 0.12s / 246MB | 0.28s / 506MB | 0.28s / 489MB | 0.42s / 658MB | 0.61s / 842MB |
| `strings` | 0.02s / 20MB | 0.07s / 85MB | 0.18s / 221MB | 0.37s / 376MB | 0.38s / 374MB | 0.50s / 433MB | 0.77s / 524MB |
| `findrefs-string` | 0.02s / 23MB | 0.03s / 78MB | 0.04s / 215MB | 0.06s / 400MB | 0.09s / 453MB | 0.04s / 330MB | 0.11s / 878MB |
| `findrefs-method` | 0.02s / 23MB | 0.05s / 83MB | 0.04s / 206MB | 0.06s / 395MB | 0.07s / 462MB | 0.07s / 638MB | 0.11s / 899MB |
| `members` | 0.01s / 20MB | 0.03s / 83MB | 0.05s / 221MB | 0.10s / 350MB | 0.10s / 365MB | 0.13s / 438MB | 0.19s / 512MB |
| `hierarchy` | 0.01s / 20MB | 0.03s / 85MB | 0.05s / 205MB | 0.09s / 364MB | 0.10s / 399MB | 0.14s / 413MB | 0.18s / 524MB |
| `disasm` | 0.01s / 20MB | 0.04s / 85MB | 0.06s / 218MB | 0.08s / 365MB | 0.10s / 371MB | 0.13s / 436MB | 0.18s / 518MB |
| `getclass` | 0.02s / 33MB | 0.61s / 196MB | 0.09s / 310MB | 0.16s / 646MB | 0.23s / 792MB | 0.29s / 1078MB | 0.40s / 1356MB |

Methodology and the ASC comparison:
[docs/benchmarks.md](docs/benchmarks.md)
([中文](docs/zh-CN/benchmarks.md)). Full subcommand reference, output
formats and match semantics:
[docs/subcommands.md](docs/subcommands.md)
([中文](docs/zh-CN/subcommands.md)).

## Documentation

| | |
|---|---|
| [Architecture](docs/architecture.md) | the three crates, the lift/structure/emit pipeline, DEX versions, invoke-custom ([中文](docs/zh-CN/architecture.md)) |
| [Subcommands](docs/subcommands.md) | the progressive-analysis reference ([中文](docs/zh-CN/subcommands.md)) |
| [Benchmarks](docs/benchmarks.md) | full-decompile and query timings across seven real APKs, methodology, comparison with ASC ([中文](docs/zh-CN/benchmarks.md)) |
| [Performance engineering](docs/optimization.md) | 5min → 6s: the six rounds, the measured dead ends, the floor analysis ([中文](docs/zh-CN/optimization.md)) |

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
