# ddc — DEX → Java decompiler in Rust

**English** | [简体中文](README.zh-CN.md)

[![CI](https://github.com/ejfkdev/ddc/actions/workflows/ci.yml/badge.svg)](https://github.com/ejfkdev/ddc/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

`ddc` decompiles Android DEX bytecode back into readable Java — at
real-world app scale, queryable like a database, and **javac-verified**:
every one of the 1,085,000 files it emits across seven real-world APKs
parses cleanly.

## Highlights

- **Fast** — a 226 MB / 20-dex APK (weibo, 98k classes) fully
  decompiles in **6.0s**, a 398 MB bundle (Lark) in **5.8s**;
  pathological classes run on deadline-bounded monitored threads
  instead of hanging the run.
- **Compiles** — the full output of all seven benchmark APKs
  (reqable, Telegram, WhatsApp, weibo, weixin, qq, lark — 1.09M
  files) passes `javac` with **zero syntax errors**; every class of
  a case-variant name pair (`X/Cua` vs `X/cua`) is preserved as
  its own file instead of the last one silently overwriting.
- **Progressive decompilation** — 20+ query subcommands (strings,
  cross-references, hierarchies, manifest, resources, per-method
  decompiles) answer in milliseconds: query metadata first, decompile
  on demand, skip the full run entirely.
- **DEX 035–041, complete** — multi-dex APKs, XAPK/APKS/APKM
  containers, invoke-custom; lambdas and string concats fold back into
  real Java (`(a) -> …`, `Cls::name`, `a + b`).
- **Reproducible output** — no timestamps; two runs diff cleanly.
- **Bilingual CLI** — messages localize automatically
  (`DDC_LANG=zh|en` forces; English fallback).
- Built on [`jdc-core`](https://crates.io/crates/jdc-core), the
  machine-neutral core shared with
  [jcdc](https://github.com/ejfkdev/jcdc).

## Install

**macOS** (Homebrew):

```bash
brew install ejfkdev/tap/ddc
```

**Windows** (Scoop):

```bash
scoop install ejfkdev/scoop-bucket/ddc
```

**cargo-binstall** (any platform — fetches the prebuilt release binary
instead of compiling):

```bash
cargo binstall ddc-cli
```

**Binaries**: every [release](https://github.com/ejfkdev/ddc/releases)
ships raw binaries (no archives) for `linux-amd64`, `linux-arm64`,
`windows-amd64`, `windows-arm64`, `macos-amd64` and `macos-arm64` —
non-macOS builds UPX-compressed.

**From source** (Rust stable):

```bash
git clone https://github.com/ejfkdev/ddc && cd ddc
cargo build --release
```

## Usage

```bash
ddc app.apk                          # full decompile → app-out/
ddc app.apk -c com.example.Foo       # one class to stdout
ddc app.apk -o - | less              # everything to stdout

ddc mainactivity app.apk             # entry point: package + launcher
ddc findrefs app.apk string token    # every const-string "token" site
ddc getmethod app.apk Foo.toString   # one method, all overloads
ddc pkg app.apk --app -o own/        # the app's own code only
```

Full options and examples: `ddc --help` (subcommand menu grouped by
workflow). The complete reference — every option's semantics, every
subcommand's output format and behavior — lives in
[docs/cli.md](docs/cli.md) ([中文](docs/zh-CN/cli.md)).

## Performance

Seven real-world APKs, release build, 3-run averages
(Apple Silicon, 6P+12E):

| APK | Size | Full decompile | Peak RSS |
|---|---|---|---|
| reqable | 34 MB | **0.28s** | 151 MB |
| Telegram | 62 MB | **8.00s** | 1301 MB |
| WhatsApp | 139 MB | **9.0s** (99,276 files — case-variant pairs all preserved) | 1240 MB |
| weibo | 226 MB | **5.98s** | 1234 MB |
| weixin | 268 MB | **16.5s** | 1400 MB |
| lark | 398 MB | **5.80s** | 1614 MB |
| qq | 374 MB | **18.04s** | 2312 MB |

Query subcommands on the same APKs (cells: time / peak RSS;
`strings -f <package> --with-locations`, `findrefs` on the package
string and method `onCreate`, `hierarchy`/`disasm`/`getclass` on each
app's launcher class):

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

## Documentation

| | |
|---|---|
| [Architecture](docs/architecture.md) | crates, the lift/structure/emit pipeline, DEX versions, invoke-custom ([中文](docs/zh-CN/architecture.md)) |
| [CLI reference](docs/cli.md) | every option and subcommand, in detail ([中文](docs/zh-CN/cli.md)) |
| [Subcommands](docs/subcommands.md) | the progressive-analysis reference ([中文](docs/zh-CN/subcommands.md)) |
| [Benchmarks](docs/benchmarks.md) | timings, memory, methodology, ASC comparison ([中文](docs/zh-CN/benchmarks.md)) |
| [Performance engineering](docs/optimization.md) | 5min → 6s: six rounds, measured dead ends ([中文](docs/zh-CN/optimization.md)) |

## Known limitations

Erased types (DEX has no Signature); d8-desugared `-$$Lambda$` classes
stay separate files; a few R8 monster methods degrade via timeout;
pattern-switch renders as desugared dispatch chains. Details:
[architecture](docs/architecture.md).

## Testing

```bash
cargo test    # 56 tests
```

## License

[MIT](LICENSE) © ejfkdev

<div align="center">
<sub><a href="README.zh-CN.md"> 简体中文</a> · 友情链接 https://linux.do </sub>
</div>
