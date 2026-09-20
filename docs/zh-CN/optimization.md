# 性能工程

[English](../optimization.md) | [简体中文]

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

#### 第七轮：分配、哈希与系统调用（weibo 5.6→4.6s；weixin 16.5→10.7s、lark 5.8→4.9s、qq 18.0→13.6s）

每项均先经 samply 采样定位再验证。顺带修复两个正确性 bug（其一存在于已发布的 v0.1.4）：值前推会改写**赋值目标**（`25 = 25;`——仅 reqable 就 242 处）；phi 提交顺序跟随哈希器迭代序（跨运行输出不稳定——reqable 5579 文件中 243 个抖动）。现在同参数双跑 diff 为零（时限守卫触发的极少数怪物方法除外）。

1. **写盘池**：worker 以 ~32 文件/批交接（每批一次锁，队列上限按文件数计）；`create_new` 打开替代每文件无条件 remove+open（4 系统调用→3，大小写变体语义由 EEXIST 回退保留，无需分片锁）；包目录树在解析期间由后台线程预建（writer 常态零 mkdir）。writer 数 = clamp(cpus/4, 2, 4)，默认 worker 数**预留**这些核（18 核上 18+4 线程双输）
2. **FxHash 全量替换**（jdc-core + ddc-dec）：universe/dominator/walk 守卫集合与每方法表原先用 SipHash-1-3 哈希 usize 键（~5% worker CPU）
3. **IR 载荷 Arc 化**：`JavaType::Object`、`Expr::{Method,Field,New}` 的类名/方法名、`MethodDescriptor`、catch 类型链、`ConstVal::Str` 全部 `Arc` 化，配合每镜像 intern 缓存（`DexRefCache`：proto→描述符、type→内部名/解析类型，OnceLock 槽位免锁）。`method_ref` 从每条 invoke 6-10 次分配（params→`format!`→重解析！）降为 0；下游全部 IR 克隆变引用计数
4. **`group_exceptions_with`**（weixin 上曾占 11.8% self）：首轮分组索引化、handler 键只算一次（原每对比较重算两份）、合并循环按键指纹分桶、间隙扫描二分窗口化（原每对全量扫 exc_ranges+blocks）、语句树遍历提升为每方法一次的前缀表、handler-protection 对按起始 pc 索引、克隆移到廉价判据之后
5. **零拷贝文本组装**：方法体以绝对缩进直接渲染进类缓冲（`Printer::with_indent`+`with_output`）——每方法中间 String、逐行重缩进、整体 `push_str` 三次全量拷贝全部消失；出处注释头直写（无每类 `format!`）；类缓冲按方法数预留（封顶 256KB）
6. **热数据借用化**：Structurer/Converter 以引用（Cow）共享每方法异常组与 dominator（原每方法 3 次深克隆）；booleanize/infer_types 持 `Vec<&TypeRef>` 且仅在类型变化时写回
7. **锁与杂项**：`DexFile::raw()`（18 线程 materialize 下每类一次互斥锁 → RwLock + `materialize_all` 每镜像一次快照提升；辅助函数内 5 次调用合并为 1 次）、环境变量读取全部 OnceLock 化（原每方法/每标识符扫描 environ）、`java_ident` 返回 Cow（干净名字零分配）、mimalloc `MIMALLOC_PURGE_DELAY=1000`（每方法 IR 突发式生灭下的 madvise 抖动）

#### 第八轮：质量轮（外部 lab 包反馈驱动）

评审者用真实 `android.jar` 对 ddc 输出做**全量 javac 编译**（而非我们的语法门）：小 lab 包 ~100 个语义错误 vs jadx 1 个。重建同形态 lab 包复现后逐一根因修复——以下每条都是 v0.1.4 的真实 bug，语法门全部看不见：

1. **null 比较反向重写**：`obj == 0` 把 LOCAL 侧换成了 null 而非 const 侧——全语料所有对象判空都渲染成 `null != 0`（仅 reqable 就 4,598 处）
2. **children_of 的 OnceLock 双 set**：先占位空表、真索引静默丢弃——成员嵌套类既不内联也不独立发射（**整个类从输出中消失**）
3. **`return null` 渲染成 `return 0`**：对象上下文（return-object/throw/引用参数/字段写入）的 const-0 在 lift 层归一为 null
4. **寄存器重定型**：stable-var 按 (block, slot) 复用并就地改类型（`byte[] v1 = …; v1 = s(v1,…)` 装 String）——键改为 (block, slot, 类型指纹)，类型变化铸造新变量
5. **静态嵌套类当 inner 渲染**（`str.new Report(…)` 吞掉首个构造参数）：d8 默认模式无嵌套注解——static 判定补结构性证据（无外部类类型的实例字段），内联成员类头补 `static`
6. **`super()` 渲染成 `new Object();`**：构造器接收者 `Local{var:0}` 未被识别为 this——lift 层归一化
7. **作用域违规**：分支内 LocalDef 被块外引用 → 前序块编号 + 内外出现计数的两遍分析提升声明；死 phi 提交残渣（`printStream = check;`）由 drop_dead_locals 清除；只写不读的变量计入 ensure_declared
8. **StringBuilder 折叠吃掉值**：append 走别名寄存器时 `toString()` 被折叠成 `""`——空 parts 永不折叠
9. **重复分配**：final read 内联折叠 new 后寄存器 Pending 视图未消费，块退出物化再发一次——内联即消费（raw new 豁免，构造器折叠仍需要它）
10. **boolean 方法返回 int**：返回位置的局部变量纳入 booleanize 证据

修复后 lab 包三种 dex 变体**全量编译 0 错**（v0.1.4 同口径 39 错）。语料重验：7 基准 APK + alipay/MinisApp ≈ 118 万文件语法零错、反编译零失败、跨运行字节稳定（lark/weixin/reqable diff=0）。代价：大语料 CPU 约 +10%（weibo 4.6→5.0s、weixin 10.7→11.6s；lark/qq 现在还渲染嵌套成员——v0.1.4 静默丢弃的输出），lark RSS +200MB（嵌套类内联）。

### 5.6s 之后的地板（若要再快）

总 CPU ~65s（user 53 + sys 12）÷ 6P+12E 核 ≈8 P 等效吞吐 ≈ 8.1s 理论并行地板；分桶：>100 块巨兽 ~20s CPU（jdc-core walk 区域探索 + dominator 每作用域重算）、6-20 块 ~13s、打印 ~5s、写盘 sys ~12s（98k 文件 APFS 元数据，writer 线程已与反编译重叠）。到 3s 级需 Expr arena 化 + dominator 子域索引 + 巨兽类算法级重写。机器方差的教训：**必须 3 连测取中位**（同参数波动 ±25%，E 核调度与内存带宽争用）。
