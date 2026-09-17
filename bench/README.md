# ddc vs ASC 渐进式分析基准

同机（Apple Silicon, 6P+12E）同查询交替执行 3 轮取中位（wall time），stdout 全部丢弃。
ASC 以其 venv（androguard+mutf8）跑 `main.py`，两工具均默认并行度。
正确性交叉验证：Telegram `type android/app/Activity` 查询，两边 (owner, method) 集合
107/107 完全重合；ASC 额外 1 条为 proto 级引用（方法签名引用类型、指令未用——
ddc 为指令级精确语义）。

```
$ bash bench/ddc_vs_asc.sh          # 结果见 ddc_vs_asc_results.txt
```

结论：findrefs（string/type/method）ddc 全部 1.9-2.7× 更快；getclass 在多 dex
大 APK 上 ASC 更快（其 zip 比特流探测只膨胀目标 dex，ddc 需解析全部镜像的
头表——~0.2s 固定底座），类本身昂贵时（Telegram）ddc 反超。
内存：findrefs ddc ~820MB vs ASC ~170MB（lark 353MB；ddc 持有整个 APK 字节 +
在途镜像，ASC 逐条目流式——mmap+madvise 可再压缩，未做）。

## rasc（ASC rust 分支）对比（2026-09，同机串行 3 轮中位）

rasc 六武器：mmap、零物化 Dex（只验表范围）、字节空间 SIMD 字符串匹配（memchr，
不解码）、操作码 UNITS/KINDS 双表、≤4 目标的原始码字节 memmem 预过滤、前缀流式
解压（类名/定位只需 ~31% 字节）+ rayon 嵌套偷取。ddc 已移植五件（见
`perf: port the rasc playbook` 提交）；战况：

| 查询 | ddc | rasc | 结果 |
|---|---|---|---|
| findrefs 无匹配（lark 353MB） | **0.03s** | 0.04s | **ddc 胜**（前缀跳过） |
| manifest | ~0.01s | ~0.01s | 平 |
| findrefs string 常见词 | 0.08s | 0.05s | rasc 1.6× |
| listclasses | 0.20s | 0.06s | rasc 3× |
| getclass | 0.37s | 0.06s | rasc（比特流定位） |

剩余差距的精确归因：①listclasses 未移植 one-probe 策略（每 chunk 全量扫
string_ids）；②getclass 未做流式定位+早停；③线程机制（我们每进程 spawn ~20
线程 vs rayon 池复用）。正确性交叉：findrefs 命中数与旧实现完全一致
（tg/lark/weibo = 124/3816/635，大小写敏感字面语义下），listclasses 类名
387,717 与 rasc 完全一致，type 查询唯一方法集合 108/108。
