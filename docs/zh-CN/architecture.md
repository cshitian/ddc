# 架构

[English](../architecture.md) | [简体中文]

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
