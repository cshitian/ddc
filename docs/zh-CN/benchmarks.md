# 基准测试

[English](../benchmarks.md) | [简体中文]

七个真实 APK —— reqable 3.2.23（34MB）、Telegram（62MB）、WhatsApp
（139MB）、weibo 16.9.1（226MB、20 dex）、weixin 8.0.78（268MB）、
飞书 8.0.2（398MB、59 dex）、qq 9.3.65（374MB）—— 墙钟时间 3 连测取
平均，峰值 RSS 来自 `/usr/bin/time -l`：

| APK | 大小 | 全量反编译 | 峰值 RSS |
|---|---|---|---|
| reqable | 34 MB | **0.28s** | 151 MB |
| Telegram | 62 MB | **8.00s** | 1301 MB |
| WhatsApp | 139 MB | **9.0s** (99,276 files — case-variant class pairs all preserved) | 1240 MB |
| weibo | 226 MB | **5.98s** | 1234 MB |
| weixin | 268 MB | **16.5s** | 1400 MB |
| lark | 398 MB | **5.80s** | 1614 MB |
| qq | 374 MB | **18.04s** | 2312 MB |

**编译验证**：七个 APK 的全部 `.java`（共 1,085,000 个文件）逐个喂给
`javac -Xmaxerrs 500000`——**语法错误为零**（其余诊断为语义级：缺少
Android classpath、重复 bridge 方法等）。

## 同一批 APK 上的全部查询子命令

3 连测取平均；单元格为 墙钟 / 峰值 RSS。查询内容：`strings -f <包名>
--with-locations`；`findrefs string <包名>`；`findrefs method onCreate`；
`hierarchy`/`disasm`/`getclass` 用各 App 的启动类（Telegram 的
`LaunchActivity` 是特别大的类）：

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

测量方法论（3 连测、串行纪律、CPU 计量陷阱）见
[英文版](../benchmarks.md) 的 Methodology notes 与
[性能工程](optimization.md)。
