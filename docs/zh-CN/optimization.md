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

### 5.6s 之后的地板（若要再快）

总 CPU ~65s（user 53 + sys 12）÷ 6P+12E 核 ≈8 P 等效吞吐 ≈ 8.1s 理论并行地板；分桶：>100 块巨兽 ~20s CPU（jdc-core walk 区域探索 + dominator 每作用域重算）、6-20 块 ~13s、打印 ~5s、写盘 sys ~12s（98k 文件 APFS 元数据，writer 线程已与反编译重叠）。到 3s 级需 Expr arena 化 + dominator 子域索引 + 巨兽类算法级重写。机器方差的教训：**必须 3 连测取中位**（同参数波动 ±25%，E 核调度与内存带宽争用）。
