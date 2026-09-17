# ddc — DEX → Java 反编译器（Rust）

[English](README.md) | **简体中文**

[![CI](https://github.com/ejfkdev/ddc/actions/workflows/ci.yml/badge.svg)](https://github.com/ejfkdev/ddc/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

`ddc` 把 Android DEX 字节码反编译回可读的 Java —— 真实 App 级别的速度，
并且可以像数据库一样查询。

```bash
$ ddc weibo.apk -o out/
ddc：已写出 98348 个文件到 out/，用时 5.54s
```

| | |
|---|---|
| 226MB / 20 dex 的 APK（weibo） | 9.8 万个类 → **5.4s** |
| 353MB / 59 dex 的飞书 | 20.8 万个编译单元 → **9.2s** |
| 在这 353MB 里搜一个字符串 | **0.07s** —— 不做全量反编译 |

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

渐进式查询速查（weibo，226MB/20dex）：

| | | | |
|---|---|---|---|
| `info` **0.11s** | `listclasses` **0.10s** | `manifest` **0.06s** | `mainactivity` **0.02s** |
| `findrefs string` **0.14s** | `findrefs type/method/field` ~0.5s | `strings` **0.04s** | `members` **0.04s** |
| `hierarchy` **0.04s** | `largest` **0.06s** | `disasm` **0.04s** | `res` **0.01s** |
| `getclass` **0.03s** | `getmethod` **0.03s** | `callers` ~0.5s | `pkg` 0.165s |

完整说明、输出格式与匹配语义：
[docs/zh-CN/subcommands.md](docs/zh-CN/subcommands.md)
（[English](docs/subcommands.md)）。

## 文档

| | |
|---|---|
| [架构](docs/zh-CN/architecture.md) | 三个 crate、提升/结构化/输出管线、DEX 版本、invoke-custom（[English](docs/architecture.md)） |
| [子命令](docs/zh-CN/subcommands.md) | 渐进式分析参考（[English](docs/subcommands.md)） |
| [基准](docs/zh-CN/benchmarks.md) | 六个真实 APK 的全量与查询耗时、方法论、与 ASC 对比（[English](docs/benchmarks.md)） |
| [性能工程](docs/zh-CN/optimization.md) | 5 分钟 → 5.4s：六轮优化、实测排除的捷径、地板分析（[English](docs/optimization.md)） |

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
