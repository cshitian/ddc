# ddc — DEX → Java 反编译器（Rust）

[English](README.md) | **简体中文**

[![CI](https://github.com/ejfkdev/ddc/actions/workflows/ci.yml/badge.svg)](https://github.com/ejfkdev/ddc/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

`ddc` 把 Android DEX 字节码反编译回可读的 Java —— 真实 App 级别的速度、
可以像数据库一样查询，并且**经过 javac 验证**：七个真实 APK 共
1,085,000 个输出文件全部零语法错误。

## 特性

- **快** —— 226MB/20 dex 的 weibo（9.8 万个类）全量反编译 **6.0s**，
  398MB 的飞书 **5.8s**；病态类跑在带截止期的受控线程上，不会拖死
  整个运行。
- **能编译** —— 七个基准 APK（reqable/Telegram/WhatsApp/weibo/weixin/
  qq/lark，共 109 万文件）的输出全部通过 javac，**零语法错误**；
  大小写仅差一位的类名对（`X/Cua` vs `X/cua`）两个类都各自成文件，
  不再后者覆盖前者。
- **渐进式反编译** —— 20+ 查询子命令（字符串、交叉引用、继承谱、
  manifest、资源、方法粒度反编译）毫秒级出答案：先查元数据、按需定点
  反编译，绝大多数分析不必付全量的代价。
- **DEX 035–041 全版本** —— 多 dex APK、XAPK/APKS/APKM 容器、
  invoke-custom；lambda 与字符串拼接折叠回真 Java（`(a) -> …`、
  `Cls::name`、`a + b`）。
- **可读输出** —— jadx 式局部变量名（`str`、`getName() → name`、
  Kotlin `Intrinsics` 参数名）取代 `v12`；IntDef 魔法数字开箱即用
  按常量名渲染（`setVisibility(8)` → `View.GONE`；内置 android-37
  域表，`--symbols` 可覆盖）。
- **可复现输出** —— 无时间戳，两次运行 diff 干净。
- **中英双语 CLI** —— 按环境变量自动识别语言（`DDC_LANG=zh|en` 强制
  指定，回退英文）。
- 基于 [`jdc-core`](https://crates.io/crates/jdc-core) —— 与
  [jcdc](https://github.com/ejfkdev/jcdc) 共用的机器无关反编译核心。

## 安装

**macOS**（Homebrew）：

```bash
brew install ejfkdev/tap/ddc
```

**Windows**（Scoop）：

```bash
scoop install ejfkdev/scoop-bucket/ddc
```

**cargo-binstall**（全平台——直接下载预编译 release 二进制，不用本地
编译）：

```bash
cargo binstall ddc-cli
```

**二进制**：每个 [release](https://github.com/ejfkdev/ddc/releases) 附带
裸二进制（无压缩包），覆盖 `linux-amd64`、`linux-arm64`、
`windows-amd64`、`windows-arm64`、`macos-amd64`、`macos-arm64`——非
macOS 平台已 UPX 压缩。

**源码构建**（Rust stable）：

```bash
git clone https://github.com/ejfkdev/ddc && cd ddc
cargo build --release
```

## 用法

```bash
ddc app.apk                          # 全量反编译 → app-out/
ddc app.apk -c com.example.Foo       # 单类输出到 stdout
ddc app.apk -o - | less              # 全部输出到 stdout

ddc info app.apk                      # App 上下文（应用名、包名、版本、
                                      # md5）+ 每镜像计数
ddc mainactivity app.apk             # 入口：包名 + 启动 Activity
ddc findrefs app.apk string token    # 每个 const-string "token" 引用点
ddc getmethod app.apk Foo.toString   # 单方法，含全部重载
ddc pkg app.apk --app -o own/        # 只反编译 App 自身代码
```

完整选项与示例见 `ddc --help`（按工作流分组的子命令菜单）。更详细的
完整参考 —— 每个选项的语义、每个子命令的输出格式与行为 —— 见
[docs/zh-CN/cli.md](docs/zh-CN/cli.md)（[English](docs/cli.md)）。

## 性能

七个真实 APK，release 构建，3 连测取平均（Apple Silicon 6P+12E）。
39 个 APK 的验证语料（408 万个反编译文件，每个 APK 的墙钟 /
峰值 RSS / javac 解析门）见
[docs/zh-CN/validation.md](docs/zh-CN/validation.md)
（[English](docs/validation.md)）。

<details>
<summary>全量反编译 —— 7 个真实 APK</summary>

| APK | 大小 | 全量反编译 | 峰值 RSS |
|---|---|---|---|
| reqable | 34 MB | **0.28s** | 151 MB |
| Telegram | 62 MB | **8.00s** | 1301 MB |
| WhatsApp | 139 MB | **9.0s**（99,276 文件——大小写变体类全部保留） | 1240 MB |
| weibo | 226 MB | **5.98s** | 1234 MB |
| weixin | 268 MB | **16.5s** | 1400 MB |
| lark | 398 MB | **5.80s** | 1614 MB |
| qq | 374 MB | **18.04s** | 2312 MB |

</details>

同一批 APK 上的查询子命令（单元格：耗时 / 峰值 RSS；`strings -f <包名>
--with-locations`，`findrefs` 查包名字符串与方法 `onCreate`，
`hierarchy`/`disasm`/`getclass` 用各 App 启动类）：

<details>
<summary>查询子命令 —— 13 个命令 × 7 个 APK</summary>

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

</details>

## 文档

| | |
|---|---|
| [架构](docs/zh-CN/architecture.md) | 三个 crate、提升/结构化/输出管线、DEX 版本、invoke-custom（[EN](docs/architecture.md)） |
| [CLI 参考](docs/zh-CN/cli.md) | 全部选项与子命令详解（[EN](docs/cli.md)） |
| [子命令](docs/zh-CN/subcommands.md) | 渐进式分析完整参考（[EN](docs/subcommands.md)） |
| [基准](docs/zh-CN/benchmarks.md) | 耗时/内存、方法论、与 ASC 对比（[EN](docs/benchmarks.md)） |
| [性能工程](docs/zh-CN/optimization.md) | 5 分钟 → 6s：六轮优化与实测排除的捷径（[EN](docs/optimization.md)） |
| [语料验证](docs/zh-CN/validation.md) | 39 个真实 APK、408 万文件全部 javac 解析零错误，含发现并修复的 bug 清单（[EN](docs/validation.md)） |

## 已知限制

擦除类型（DEX 无 Signature）；d8 反糖的 `-$$Lambda$` 类独立成文件；极少数
R8 巨兽方法超时降级；pattern-switch 呈现为反糖分发链。详见
[架构文档](docs/zh-CN/architecture.md)。

## 测试

```bash
cargo test    # 56 个测试
```

## 许可

[MIT](LICENSE) © ejfkdev
