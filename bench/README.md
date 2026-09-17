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
