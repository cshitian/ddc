# ddc — DEX → Java 反编译器（Rust）

[English](README.md) | **简体中文**

[![CI](https://github.com/ejfkdev/ddc/actions/workflows/ci.yml/badge.svg)](https://github.com/ejfkdev/ddc/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

`ddc` 把 Android DEX 字节码反编译回可读的 Java —— 真实 App 级别的速度，
并且可以像数据库一样查询。

```bash
$ ddc weibo.apk -o out/
ddc：已写出 98348 个文件到 out/，用时 6.13s
```

| | |
|---|---|
| 398MB / 59 dex 的飞书 | 20.8 万个编译单元 → **6.1s** |
| 374MB 的 QQ（巨兽） | **17.9s** |
| 在这 398MB 里搜一个字符串 | **0.04s** —— 不做全量反编译 |

## 特性

- **DEX 035–041 全版本支持** —— 多 dex APK、XAPK/APKS/APKM 分包容器、
  `invoke-polymorphic` / `invoke-custom`；lambda 与字符串拼接调用点折叠回
  真 Java（`(a) -> …`、`Cls::name`、`a + b`）。
- **20+ 渐进式子命令** —— 字符串、交叉引用、类继承谱、manifest、资源、
  方法粒度反编译 —— 毫秒级出答案，先于任何全量反编译。
- **真实世界加固** —— 病态类跑在带截止期的受控线程上而不是拖死整个
  运行；每类 panic 隔离。
- **可复现输出** —— 无时间戳，两次运行 diff 干净。
- **中英双语 CLI** —— 按环境变量自动识别语言（`DDC_LANG=zh|en` 强制
  指定；回退英文）。
- 基于 [`jdc-core`](https://crates.io/crates/jdc-core) —— 与
  [jcdc](https://github.com/ejfkdev/jcdc) 共用的机器无关反编译核心。

## 安装

每个 [release](https://github.com/ejfkdev/ddc/releases) 附带各平台预编译
二进制（Linux x86_64/aarch64、macOS x86_64/Apple 芯片、Windows x86_64）
—— **裸二进制，无压缩包**；非 macOS 平台已 UPX 压缩。打 tag 即触发
CI 构建，二进制版本号等于 tag 版本。

源码构建（Rust stable）：

```bash
git clone https://github.com/ejfkdev/ddc && cd ddc
cargo build --release        # release profile 自带 fat LTO + 1 CGU
./target/release/ddc --help
```

## 用法

```bash
ddc app.apk                          # 全量反编译 → app-out/
ddc app.apk src/                     # dae/pycdc 风格位置参数输出
ddc app.apk -c com.example.Foo       # 单类输出到 stdout
ddc app.apk -o - | less              # 全部输出到 stdout

ddc mainactivity app.apk             # 入口：包名 + 启动 Activity
ddc findrefs app.apk string token    # 每个 const-string "token" 引用点
ddc getmethod app.apk Foo.toString   # 单方法，含全部重载
ddc pkg app.apk --app -o own/        # 只反编译 App 自身代码
ddc manifest app.apk --component launcher   #（详见 --help）
```

`ddc --help` 输出完整选项、按工作流分组的子命令菜单与示例 —— 用你的
语言。

## 性能

七个真实 APK，release 构建，墙钟时间 3 连测取平均；峰值 RSS 来自
`/usr/bin/time -l`。机器：Apple Silicon（6P+12E）。

| APK | 大小 | 全量反编译 | 峰值 RSS |
|---|---|---|---|
| reqable | 34 MB | **0.27s** | 147 MB |
| Telegram | 62 MB | **8.09s** | 1016 MB |
| WhatsApp | 139 MB | **8.67s** | 1197 MB |
| weibo | 226 MB | **6.13s** | 1238 MB |
| weixin | 268 MB | **10.15s** | 1413 MB |
| lark | 398 MB | **6.08s** | 1580 MB |
| qq | 374 MB | **17.85s** | 2330 MB |

同一批 APK 上全部查询子命令（单元格：墙钟 / 峰值 RSS）。查询内容：
`strings -f <包名> --with-locations`；`findrefs string <包名>`；
`findrefs method onCreate`；`hierarchy`/`disasm`/`getclass` 用各 App 的
启动类（Telegram 的 `LaunchActivity` 是特别大的类）：

| 子命令 | reqable | Telegram | WhatsApp | weibo | weixin | lark | qq |
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

方法论与 ASC 对比：[docs/zh-CN/benchmarks.md](docs/zh-CN/benchmarks.md)
（[English](docs/benchmarks.md)）。完整子命令参考、输出格式与匹配语义：
[docs/zh-CN/subcommands.md](docs/zh-CN/subcommands.md)
（[English](docs/subcommands.md)）。

## 文档

| | |
|---|---|
| [架构](docs/zh-CN/architecture.md) | 三个 crate、提升/结构化/输出管线、DEX 版本、invoke-custom（[English](docs/architecture.md)） |
| [子命令](docs/zh-CN/subcommands.md) | 渐进式分析参考（[English](docs/subcommands.md)） |
| [基准](docs/zh-CN/benchmarks.md) | 七个真实 APK 的全量与查询耗时、方法论、与 ASC 对比（[English](docs/benchmarks.md)） |
| [性能工程](docs/zh-CN/optimization.md) | 5 分钟 → 6s：六轮优化、实测排除的捷径、地板分析（[English](docs/optimization.md)） |

## 已知限制

擦除类型（DEX 无 Signature）；d8 反糖的 `-$$Lambda$` 类独立成文件；极少数
R8 巨兽方法超时降级；pattern-switch 与字符串 switch 呈现为反糖分发链。
详见 [docs/zh-CN/architecture.md](docs/zh-CN/architecture.md)。

## 测试

```bash
cargo test    # 56 个测试：解码/端到端 + CLI + 子命令集成
```

## 许可

[MIT](LICENSE) © ejfkdev。[`jdc-core`](https://crates.io/crates/jdc-core)
同为 MIT。
