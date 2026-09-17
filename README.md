# ddc — DEX 反编译器（Rust）

`ddc` 是一个用 Rust 编写的 Android DEX → Java 反编译器。它复用
[`jdc-core`](https://crates.io/crates/jdc-core)（机器无关反编译核心：CFG
结构化、语句转换、Java 输出），为 Dalvik 寄存器机实现了完整前端 —— 与
[jcdc](https://github.com/ejfkdev/jcdc)（JVM classfile 前端）同源的架构：

```text
ddc-dex (机器相关)                     jdc-core (机器无关)
──────────────────                    ──────────────────
DEX 解析（header/ids/class_def/code）  cfg::Cfg            块 + 边
Dalvik 指令解码（全 opcode + payload）  ir::BlockResult     stmts + term
寄存器→IR 提升（表达式追踪/phi）  ───►  structure/sese      区域树
机器惯用法（ctor 折叠/SB 拼接/…）       convert::Converter   Stmt 树
精炼 pass（拷贝前推/类型推断/…）         emit::Printer       Java 源码
```

## 构建与使用

```bash
cargo build --release   # release profile 自带 LTO fat + codegen-units=1

./target/release/ddc --help          # 完整帮助
```

输入支持（可多个，合并进一个类池，重名类自动去重）：

- `.dex` 镜像（035-041 任一版本）
- `.apk` / `.jar` / `.zip`（内含 `classes.dex`、`classes2.dex`…，解压+解析并行）
- 目录（递归扫描上述扩展名）

输出三选一：**目录**（按包路径落盘 `.java`）、**单个 `.java` 文件**（仅 `-c` 单类或单类输入）、**stdout**（`-`，带 `// ===== class =====` 分隔，单线程保证池序）。无输出参数时默认写到输入旁的 `<输入名>-out/`；单类输出（`-c`）默认打印到 stdout。

```bash
# 位置参数风格（dae/pycdc）：最后一个是输出目录
./target/release/ddc app.apk outdir

# 显式 -o：目录 / 单文件 / stdout
./target/release/ddc app.apk -o outdir/
./target/release/ddc app.apk -c com.example.Foo -o Foo.java
./target/release/ddc app.apk -o - | less

# 分体输入合并（apk + 补丁 dex → 一个池）
./target/release/ddc base.apk patch.dex -o merged/

# 目录输入（递归收集）+ 单类 + 列出类名
./target/release/ddc dump/ -o src/
./target/release/ddc app.apk -c com.example.Foo
./target/release/ddc app.apk -l
```

| 选项 | 说明 |
|---|---|
| `-o, --output <path>` | 输出：目录 / `file.java`（单类）/ `-`（stdout） |
| `-c, --class FQCN` | 只反编译一个类（默认 stdout） |
| `-l, --list` | 列出类名后退出 |
| `-t, --threads <n>` | 并行 worker 数（默认 CPU 数；stdout 模式强制单线程保序） |
| `--no-comments` | 去掉出处注释头 || `-v, --verbose` | stderr 输出逐 dex 统计与慢类 |
| `-h / -V` | 帮助 / 版本；支持 `--opt=value` 写法 |

位置参数歧义规则：无 `-o` 时，最后一个位置参数若**不是输入形态**（无 dex 类扩展名、不是文件、也不是含 dex 文件的目录）则视为输出——预创建的空输出目录或上次运行的输出目录都算输出（`ddc app.apk out/`，out/ 已存在且只含 .java ✓）。真输入目录（内含 dex/apk/jar/zip）即使是最后一个位置参数也保持输入（`ddc a.dex dump/` ✓）。空目录作输入会明确报错。

退出码：`0` 全部成功；`1` 有类失败（如病态 CFG 超时）；`2` 用法错误（打印完整帮助）。

每个 `.java` 的出处注释头（`--no-comments` 关闭）：

```java
// Decompiled by https://github.com/ejfkdev/ddc 0.1.0
// From: app!classes3.dex (DEX 038)      ← 输入文件 + dex 镜像 + DEX 版本
// Source file: Foo.java                  ← dex 的 SourceFile 属性
```

刻意**不含时间戳**：方便两次运行 diff 与回归测试（注意：极少数变量编号仍受 std HashMap 随机种子影响存在运行间微差，语义等价）。多 dex
APK 里 `From:` 是定位类所在镜像的最快线索（jadx 的 `loaded from:` 模式）。
运行结束在 stderr 打一行摘要（含总用时，从进程启动到落盘完成计）：
`ddc: wrote 98348 file(s) to out/, 1 failed in 5.54s`；`-l` 与 stdout 模式
同样计时。

## 架构

### crates/ddc-dex — DEX 容器与指令解码

- `DexFile`：header / string(MUTF-8) / type / proto / field / method /
  class_def 惰性容错解析（越界返回哨兵而非失败）
- `insn`：全部 Dalvik 指令（0x00–0xff，含 038 的
  `invoke-polymorphic`/`invoke-custom`/method-handle）与三种 payload
  伪指令；所有指令带**绝对跳转目标**，nibble 布局依据
  `B|A|op`（12x/11n/22c/22t/22s）与 `A|G|op`（35c）两类分别处理
- `code`：`code_item` + try 表 + `encoded_catch_handler`（含两种
  handler_off 偏移约定）
- `annotations`：encoded_value / 嵌套类注解 / 静态字段初始值

### crates/ddc-dec — 反编译前端

- **lift.rs**：寄存器文件建模为每寄存器的*值视图*：
  `Live(v)`（局部 v，语句已发射）/ `Pending(e)`（纯表达式，存储延迟以
  便嵌套）/ `PendingCall(e)`（调用结果恰好一次消费）。块出口物化非纯
  值，跨块只传播纯值、局部与开放的 `new` 视图。构造器折叠
  （`new-instance` + `invoke-direct <init>`）、d8 丢弃返回值的
  `StringBuilder.append` 语句链、`fill-array-data` 填充都在此处处理。
- **method.rs**：不动点迭代 + 合并 phi（分歧寄存器按写 pc 排序发射赋值；
  引用兄弟 phi 的值先快照进临时变量，正确表达寄存器轮转
  `a=b; b=a%b`）；入口即循环头（d8 回边到 pc 0）时入口侧 phi 以
  方法体顶部 `LocalDef` 初始化；异常处理块入口取 try 入口状态近似。
- **passes.rs**：catch 参数绑定、三元折叠（`if/else` 同变量赋值）、
  `StringBuilder` 链 → `+` 拼接（语句级 append 吸收判定）、
  `synchronized` 恢复（d8 monitor 模式）、单用途临时变量拷贝前推
  （纯值任意处、非纯值仅邻接，多赋值引用防陈旧捕获）、证据驱动类型
  推断（调用点形参/返回/字段/收发者）、布尔化与 null 比较、声明清理。
- **ctx.rs**：`jdc_core::Ctx` 的 DEX 实现（嵌套类来自
  dalvik 注解 + `$` 启发式；类型层级遍历；构造器元数查询）。
- **classdec.rs**：类头/字段（静态初始值）/方法签名/嵌套成员类内联
  渲染；匿名/局部/`-$$Lambda$` 类单独成文件。

### crates/ddc-cli — 命令行

自带极小 ZIP 读取器（stored/deflate），APK 中按
`classes.dex, classes2.dex, …` 数值序合并多 dex（重名类首个生效）。

## DEX 版本支持

支持全部标准 DEX 版本：**035、037、038、039、040、041**（magic 校验 + 拒绝未知版本；036 为非官方 odex 时代标记，ART 亦不接受）。各版本容器布局一致，差异在特性信号：

- **035**：基础格式（绝大多数 APK）
- **037+**：`invoke-polymorphic`（45cc/4rcc）、`invoke-custom`（35c/3rc）、`const-method-handle`、`const-method-type`
- **038/039**：d8 按 min-api ≥ 26 / 28 标记（默认方法 / invokedynamic 免反糖信号）
- **040/041**：ART 内部标记（验证状态），容器不变

**invoke-custom 完整解析**（DEX 037+，`d8 --no-desugaring` 产物）：

- `call_site_id`（map 0x0007）与 `method_handle`（map 0x0008，`HHHH` 布局）表从 map_list 解析
- `LambdaMetafactory` 站点 → 真实 Java 语法：非捕获 lambda 渲染为 `(a0) -> Cls.lambda$run$0(a0)`，方法引用为 `Cls::name`（SAM 参数取自实例化类型链接参数）
- `StringConcatFactory` 站点 → recipe 解析并折叠回 `+` 拼接表达式
- `const-method-handle` → `Cls::name` 字面量

## 渐进式分析（子命令）

参考 ASC 的"把编译产物当数据库查"理念：超大 APK 不必全量反编译（weibo 全量
5.5s），先查元数据再定点反编译——元数据加载只需解压+解析 dex 头表（weibo
20 个镜像并行约 0.35s），扫描不经过提升/结构化/渲染管线：

| 命令 | 作用 | weibo (236MB/20dex) |
|---|---|---|
| `ddc manifest app.apk` | AndroidManifest.xml（二进制 AXML）→ 文本 XML，不碰 dex | **0.06s** |
| `ddc findrefs app.apk string token` | 全部字符串字面量引用（常量指令扫描） | **0.14s** |
| `ddc findrefs app.apk type com.example.Foo` | 类型引用（new-instance/check-cast 等） | ~0.5s |
| `ddc findrefs app.apk method onCreate --class android/app/Activity` | 方法调用点 | ~0.5s |
| `ddc findrefs app.apk field CREATOR --class com.example --fuzzy-class` | 字段读写点 | ~0.5s |
| `ddc listclasses app.apk [pattern]` | 类名清单，可模糊过滤 | **0.10s** |
| `ddc info app.apk` | 每镜像 dex 版本/类/方法/字段/字符串计数 | **0.11s** |
| `ddc getclass app.apk com.example.Foo [-o F.java]` | 单类（含嵌套）定点反编译 | **0.03s**（典型类） |
| （全量对照）`ddc app.apk -o out/` | 98,348 个类全部反编译落盘 | 5.45s / 1.28GB |

**定位类在哪个 dex**：`--dex NAME`（可重复，条目名子串匹配）把范围缩到指定镜像——
过滤发生在解析之前（`getclass --dex classes20` 只解析一个镜像，weibo 上 0.09s）；
类名出现在多个镜像时 `getclass` 会警告并列出镜像与 `--dex` 提示；`--dex` 传错时
错误信息列出全部可用条目名。stdout 输出模式完全干净（stderr 静默），耗时只随
`-o` 文件/目录输出打印；`findrefs -o FILE` 把命中行写入文件并打印耗时。

`findrefs` 输出每行一个引用点（按类/方法排序，机器可 grep）：

```
Hello.main([Ljava/lang/String;)V  ->  invoke Greeter->greet()Ljava/lang/String;
Hello.main([Ljava/lang/String;)V  ->  sput Hello->counter:I
```

匹配语义：string/type/名称为子串（大小写不敏感）；`--class` 默认精确（
`com.poc.Main`/`com/poc/Main`/`Lcom/poc/Main;` 三种写法都归一化），加
`--fuzzy-class` 变子串。扫描为每镜像一线程并行；命中 0 个时秒回。
AXML 解码器在 `ddc-cli/src/axml.rs`（字符串池 UTF-16/UTF-8 双格式、属性
typedValue 渲染），输入也接受裸 `.axml` 文件。渐进式工作流：
`info → listclasses → findrefs → getclass`，最后才按需全量。

### 对比 ASC（同机同查询交替 3 轮取中位，`bench/`）

5 个真实 APK（62-353MB）渐进式查询，stdout 丢弃；正确性交叉验证 107/107 重合：

| 查询 | ddc | ASC | 倍率 |
|---|---|---|---|
| findrefs string（lark 353MB） | **0.32s** | 0.61s | 1.9× |
| findrefs string（weixin 268MB） | **0.22s** | 0.52s | 2.4× |
| findrefs string（weibo 226MB） | **0.19s** | 0.44s | 2.3× |
| findrefs type/method（全部 5 个） | **0.09-0.31s** | 0.29-0.66s | 2-3× |
| getclass（lark/weixin/weibo） | 0.18-0.42s | **0.10-0.12s** | ASC 快 |
| getclass（Telegram，类本身大） | **0.05s** | 0.11s | ddc 快 |
| findrefs 内存（lark） | ~820MB | ~170MB | ASC 省 |

getclass 的分野：ASC 用 zip 比特流探测定位后**只膨胀目标 dex**（多 dex 大 APK
上底座更低）；ddc 解析全部镜像头表（~0.2s 底座）后 lazy 物化——类本身昂贵时
反超，类便宜时让位于底座。findrefs 的扫描域 ddc 全面更快（流水线：解析波次
产出 → 有界通道 → 扫描线程消费即丢弃；Arc 共享 APK 字节消除压缩副本）。

## 真实 APK 基准

| APK | 类数 | 结果 | 耗时 | 峰值内存 |
|---|---|---|---|---|
| reqable-app-android-arm64 | 8,201 | 5,579/5,579 编译单元，0 失败 | **0.24s** | **270MB** |
| weibo 16.9.1（236MB，20 个 dex） | 145,492 | 98,348/98,349（1 个 gson TypeAdapter 病态类超时降级） | **5.6s** | ~1.5GB |

关键性能工程（每项均经栈采样定位）：

1. **指数 Pending 增长**（内存主根因，9.8GB→157MB）：循环携带的寄存器 Pending 表达式在 fixpoint 每轮被合并点整体克隆，树随迭代翻倍——`write()` 中超过 96 节点的表达式直接物化为局部变量，状态树从此有界
2. **指数遍历**：`stmt_collect_vars` 在 `walk_all` 闭包内递归自身，每层嵌套双重遍历（O(2^深度)）——改纯递归单遍（单类 90s→0.17s）
3. **全量重算 fixpoint**：旧轮式循环每轮深克隆+深比较全部寄存器状态（Expr 树）——改为 worklist + 输出版本戳，仅重算前驱变化的块
4. **双重解码**：风险检查与池化各对全部 145k 方法做完整指令解码——改为 code_item 头字段 peek（8 字节）
5. **计数器 SipHash**：前推 pass 的 HashMap 计数/记录三趟全树遍历——融合为单趟 + Vec 索引
6. **超时阻塞**：病态类在受控线程（64MB 栈）中反编译、5 秒截止；线程登记后 worker 立即继续（尾部统一回收，总成本 ≤ 一个截止期）；阈值按真实负载校准（常规 R8 大方法 ≤11k 指令，指数 walk 的 gson adapter ≥24k → 16k 分界）
7. 多 dex **并行解压+解析**（inflate 与 header/字符串/注解码同线程）
8. **动态工作队列**（32 类小片 + 原子游标）：静态等分块在 P/E 混合核上产生长尾（E 核线程拖完全程）——小片拉取让慢核自然少领
9. **单块快速通道**：单基本块方法（R8 产物中 >50%）无控制流可结构化，跳过结构化器/转换器/控制流 pass
10. **writer 线程池**（有界 MPMC 队列）：98k 文件 × 992MB 的落盘与反编译解耦——内联 fs::write 曾让 worker 在 APFS 元数据上阻塞 64s（"busy"≠CPU）；写者持有各自 mkdir 缓存
11. **环境变量门控的插桩**（相位/分桶计时、DOM 计数器）全部 OnceLock/AtomicBool 化——`env::var` 每 方法一次是 716k 次锁+查找

### 六轮优化的累计战果

| 轮次 | weibo | 关键修复 |
|---|---|---|
| 基线 | 5min | — |
| 第一轮 | 110s | 指数 Pending 物化上限（内存 9.8GB 根因）、指数遍历、worklist、双解码、非阻塞超时 |
| 第二轮 | 90s | 动态工作队列（P/E 核失衡）、单块快速通道、目录缓存 |
| 第三轮 | 57s | **mimalloc**、签名门先行、merge 借用 sides、try-entry 快照、cleanup 8→3、**LTO fat + native CPU** |
| 第四轮（jdc-core） | 24s | 见下 |
| 第五轮 | 19.6s | **稳定变量 ID**：`fresh_var` 每次重建分配新 ID → out 状态永不相等 → worklist 级联（30M 块重建）；`(block, reg) → var_id` 跨重建复用 |
| 第六轮 | **5.6s** | 见下 |

#### 第四轮：jdc-core 结构化器算法优化（全部叠加式，默认行为不变）

采样热点从 ddc 前端迁移到 jdc-core 的异常分组/作用域机制后，四处修复（jdc-core 14 测试 + jcdc 31 测试全过，**不影响 jcdc**）：

1. **`group_exceptions_with`**：O(G²) 合并循环里每对比较都重新分配+排序 `handler_key` —— 预计算一次、合并时增量维护（weibo 57→23s 的主贡献）
2. **`sub_scope`**：每次调用克隆 universe 两份 + `holds_start` 全块线性扫 + 跨度扩展全块扫（O(B·G)）—— 去克隆、`block_at_start` 哈希索引、`starts_partition` 二分切片
3. **`expand_orphan_group_tails`**：嵌套 `groups × out` any 扫描（O(G·|out|)）—— 一次遍历物化 `groups_in_out`；`start_held` 全块扫 → 索引
4. **`compute_dominators`**：每条边 HashSet 哈希查询 → 一次性位集（数组探测）；**`Printer::into_string` 的 `truncate_dead_ends`** 无条件深克隆整棵语句树 → 只读探测、罕见死端才克隆

#### 第六轮：前端与管线（每项均测量验证）

1. **`Block.ins` 切片化**：每块深克隆整段指令（等价于全部方法二次解码）→ `DexCfg` 持有 insns 流，块存 `[lo, hi)` 索引；`CodeItem` 按 `&mut` 移交
2. **`group_exceptions_with` 键值 intern**：怪物类（gson adapter 数百个同 handler try 区间）的 O(G²) 重启扫描里 `Vec<Vec<(u32, Option<String>)>>` 深比较主导全部耗时——intern 成 u32 id 比较；**结果共享**：Structurer 与 Converter 各算一遍（外加每轮预算重试再算）→ 每方法算一次传入（新增 `with_precomputed_groups` / `with_precomputed`，jcdc 旧 API 不变）
3. **`booleanize` 二次方**：`for i in 0..n { walk_all(...) }` 每变量全树重扫——2000 变量 × 15k 语句的巨兽 = 30M 次访问/方法 → 单遍收集 (any, all_bool)
4. **`ensure_declared` 死遍历**：`assigned` 集合收集后从未使用（每方法一趟全树 + HashSet）——删除；`params/declared` HashSet → 稠密 `Vec<bool>`
5. **fixpoint 每访问成本**：try-entry 判定每次访问重扫全部异常区间（含 block_at 二分）+ handler catch 类型 String 克隆 → 循环外预计算 `try_entry_flags` / `handler_types`（weibo 14.1→10.6s 的主贡献）
6. **pass 特征门控**：lift 时置位 SB/monitor/cmp 标志（`MethodFlags` 经 `&mut` 逃逸出被消耗的 lifter）——无 StringBuilder 的方法跳过 `fold_string_builders` 全套分析，无 monitor 跳过 `fold_synchronized`；`fused_expr_rewrites` 一遍完成 cmp 残留+null 比较+const 前置（原三趟）
7. **DexPool 借用化**：`children_of`/`outer_of` 每类一次的 Vec/String 克隆 → 借用切片
8. **5s 受控线程截止**：唯一真超时的 StatusTypeAdapter 的 10s 截止期是尾 draining 的关键路径（work 4.3s 后空等 6s）；5s 时其余受控类仍在期限内完成

### 5.6s 之后的地板（若要再快）

总 CPU ~65s（user 53 + sys 12）÷ 6P+12E 核 ≈8 P 等效吞吐 ≈ 8.1s 理论并行地板；分桶：>100 块巨兽 ~20s CPU（jdc-core walk 区域探索 + dominator 每作用域重算）、6-20 块 ~13s、打印 ~5s、写盘 sys ~12s（98k 文件 APFS 元数据，writer 线程已与反编译重叠）。到 3s 级需 Expr arena 化 + dominator 子域索引 + 巨兽类算法级重写。机器方差的教训：**必须 3 连测取中位**（同参数波动 ±25%，E 核调度与内存带宽争用）。

## 已知限制（v1）

- 泛型信息：DEX 无 Signature 属性，输出为擦除类型
- lambda：d8 反糖后的 `-$$Lambda$` / `LambdaTest$N` 类不做内联（按独立类输出）；原生 invoke-custom 站点见上文
- 病态 CFG：极少数 R8 生成的方法（weibo 的 4 个 gson TypeAdapter）触发共享结构化器的指数 walk，超时降级
- pattern-switch：d8 反糖为 `switchDispatch` if 链，不还原 `switch`
  模式匹配；字符串 switch 呈现为 hashCode 分发链
- 循环内 `append` 不折叠进拼接表达式（重复语义无法用拼接表达）
- `accumulate` 一类循环中 d8 逐次求值的 `length()` 保持在循环体内
- 异常处理块对 try 内写入的寄存器取 try 入口近似（主流
  catch-读-前置值 模式正确）

## 测试

```bash
cargo test          # 36 个：解码/端到端 + CLI + 子命令集成
```

包含端到端 fixture（真实 d8 构建的 `tests/fixtures/hello.dex`：断言
`return "hi " + this.name;` 拼接折叠与 `new Greeter("world").greet()`
构造器嵌套）、寄存器机前推的形状回归、13 个 CLI 集成用例
（`ddc-cli/tests/cli.rs`：位置参数歧义规则、输出三形态、目录输入递归、
多输入合并去重、stdout 分隔符与池序、退出码 0/1/2、出处头与总用时），
以及 8 个子命令用例（`ddc-cli/tests/subcommands.rs`：真 AXML fixture 的
manifest 解码、listclasses 过滤、getclass 单类/未知类、findrefs 四种查询
与类过滤/错误路径）。
