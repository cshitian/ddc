# ddc corpus validation

**39 real-world Android apps, 6.4 GB, 5,409,658 classes, 4,081,503 decompiled files — every one of them parses.**

Single serial run per APK on an otherwise idle machine (Apple
Silicon, 6P+12E); wall time and peak RSS via `/usr/bin/time -l`. The
syntax gate is javac's parse phase
(`-XDshould-stop.ifNoError/ifError=PARSE`), which parses every emitted
`.java` and stops before attribution — so the counts carry no
missing-classpath noise.

## Bugs found (and fixed) during validation

The corpus earned its keep on round one — 27 of 39 APKs failed the javac
parse gate, exposing seven real defects (all fixed, each verified):

| # | Symptom (first-pass errors) | Root cause | Fix |
|---|---|---|---|
| 1 | 2,518–46,774 errors/APK on renamed classes (MinisApp, WhatsApp, AutoClaw, 22 APKs total) | After a case-variant rename (`Y2.a` vs `y2.a` → `y2.a_2`), the constructor and file name took the new name but the **class header did not** — `a_2(...)` inside `class a` reads as a method with no return type | `emit_class_body` header follows the rename |
| 2 | Alipay >500k errors (hit the -Xmaxerrs cap) | A field/param named with a single non-ASCII char (`支`) — the identifier sanitizer maps every illegal char to `_`, and a one-char name lands on **bare `_`** (reserved since Java 9) | Both `java_ident`s escape a `_` result to `__` |
| 3 | Taobao 1 / DingTalk 20 errors | Classes named `var`-style restricted contextual identifiers (forbidden in type declarations since Java 10) | `var/yield/record/sealed/permits` join the keyword escape lists (declaration/reference/filename stay consistent) |
| 4 | nova (Doubao) 46 errors | Digit-start field names `1x`/`2x` — the declaration side escaped them, the **jdc-core reference side did not** | jdc-core `java_ident` gains the digit-start branch |
| 5 | Zhihu (bangcle) 423 / DingTalk residuals | The segment sanitizers for type references (`sanitize_fq`/`sanitize_source_name`) lacked the lone-underscore guard | Same guard as bug 2, applied to the segment sanitizers |
| 6 | DingTalk residual 5 | R8 class names ending in `$` (`ThreadMsg$$$`) — `rsplit('$')` yields an **empty segment**, and the qualified-new rendered `v9.new (args)` | Three empty-`$`-segment sites fall back to the full simple name |
| 7 | UU remote: whole run aborted | A fake `.dex` in `assets/` (encrypted payload, bad magic) — one bad image killed the full decompile | `parse_images` skips unparsable images (stderr notice); errors only when nothing parses |

## Full decompile

| App | Package | Version | Size | MD5 | DEX | Classes | Wall | Peak RSS | Files | Parse errors |
|---|---|---|---|---|---|---|---|---|---|---|
| 滴滴 | `com.sdu.didi.psnger` | 8.0.14 | 70 MB | `938b1d94` | 8 | 85,460 | 3.90s | 746 MB | 63,039 | 0 |
| 高德地图 | `com.autonavi.minimap` | 17.00.0.2005 | 186 MB | `e63b59b0` | 8 | 73,064 | 2.58s | 809 MB | 52,954 | 0 |
| 学信网 | `cn.com.chsi.chsiapp` | 2.5.13 | 130 MB | `5222c338` | 1 | 4 | 0.04s | 29 MB | 4 | 0 |
| 中国移动 | `com.greenpoint.android.mc10086.activity` | 12.5.4 | 219 MB | `d32b44be` | 1 | 7 | 0.07s | 3 MB | 6 | 0 |
| 招商银行 | `cmb.pb` | 14.4.0 | 159 MB | `6baf69c9` | 14 | 41,051 | 2.94s | 452 MB | 30,746 | 0 |
| 智谱清言 | `com.zhipuai.qingyan` | 3.7.9 | 98 MB | `f11f004a` | 3 | 29,329 | 0.95s | 303 MB | 18,540 | 0 |
| Minis | `com.openminis.app` | 1.13 | 39 MB | `c0d167a7` | 1 | 7,772 | 5.09s | 541 MB | 7,748 | 0 |
| 网易云音乐 | `com.netease.cloudmusic` | 9.5.95 | 224 MB | `b38a4723` | 21 | 177,777 | 5.56s | 1148 MB | 101,390 | 0 |
| Telegram | `org.telegram.messenger.web` | 12.10.2 | 62 MB | `f4abf9c8` | 4 | 20,134 | 7.85s | 1172 MB | 19,282 | 0 |
| 京东 | `com.jingdong.app.mall` | 16.0.0 | 85 MB | `1a78ab63` | 14 | 84,489 | 3.03s | 1088 MB | 61,628 | 0 |
| WhatsApp | `com.whatsapp` | 2.26.36.75 | 139 MB | `569cf81e` | 12 | 100,350 | 8.12s | 1197 MB | 99,276 | 0 |
| 支付宝 | `com.eg.android.AlipayGphone` | 12.12.26.8100 | 177 MB | `7fb233eb` | 21 | 179,460 | 9.31s | 1364 MB | 139,736 | 0 |
| AutoClaw | `com.zai.autoclaw` | 1.5.0 | 64 MB | `b80a00ed` | 2 | 20,852 | 1.59s | 415 MB | 20,079 | 0 |
| AutoGLM | `com.zhipu.agent` | 2.0.20 | 122 MB | `55086238` | 4 | 43,516 | 1.77s | 545 MB | 33,296 | 0 |
| 懂车帝 | `com.ss.android.auto` | 9.0.8 | 174 MB | `e3148f92` | 27 | 213,523 | 7.98s | 1385 MB | 163,517 | 0 |
| 抖音 | `com.ss.android.ugc.aweme` | 40.5.0 | 339 MB | `bb10859f` | 54 | 527,000 | 34.08s | 3096 MB | 518,484 | 0 |
| 百度 | `com.baidu.searchbox` | 15.76.0.10 | 160 MB | `d43d5c5d` | 21 | 185,901 | 5.28s | 1088 MB | 99,574 | 0 |
| DeepSeek | `com.deepseek.chat` | 2.5.2 | 14 MB | `538e8991` | 3 | 13,311 | 0.82s | 371 MB | 12,481 | 0 |
| 知乎 | `com.zhihu.android` | 11.10.0 | 163 MB | `d2e27da3` | 18 | 167,486 | 4.93s | 1003 MB | 107,119 | 0 |
| Meituan | `com.sankuai.meituan` | 12.66.202 | 98 MB | `c368a84e` | 12 | 118,168 | 3.91s | 831 MB | 76,048 | 0 |
| 哔哩哔哩 | `tv.danmaku.bili` | 9.12.0 | 207 MB | `22eeb540` | 32 | 302,829 | 10.58s | 1741 MB | 221,232 | 0 |
| Kimi | `com.moonshot.kimichat` | 3.1.0 | 34 MB | `2196a886` | 3 | 29,752 | 1.63s | 511 MB | 27,941 | 0 |
| Lark | `com.larksuite.suite` | 8.0.2 | 398 MB | `ad291240` | 49 | 292,118 | 5.83s | 1519 MB | 118,502 | 0 |
| MiniMax | `com.xproducer.yingshiai` | 4.11.1 | 33 MB | `b453a746` | 10 | 30,505 | 1.01s | 420 MB | 18,196 | 0 |
| 拼多多 | `com.xunmeng.pinduoduo` | 8.17.0 | 95 MB | `9bb8ba84` | 6 | 57,336 | 1.92s | 535 MB | 39,069 | 0 |
| Toutiao | `com.ss.android.article.news` | 18.5.0 | 176 MB | `2855fb2f` | 33 | 306,489 | 15.67s | 1729 MB | 286,767 | 0 |
| 豆包 | `com.larus.nova` | 15.1.0 | 395 MB | `62d70e63` | 40 | 474,226 | 16.50s | 2550 MB | 346,129 | 0 |
| QQ | `com.tencent.mobileqq` | 9.3.65 | 374 MB | `8e1f7337` | 41 | 428,076 | 16.34s | 2240 MB | 329,101 | 0 |
| Reqable | `com.reqable.android` | 3.2.23 | 34 MB | `948d4b61` | 1 | 8,201 | 0.31s | 142 MB | 5,579 | 0 |
| DingDing | `com.alibaba.android.rimet` | 8.5.5 | 317 MB | `0833d290` | 33 | 193,909 | 6.54s | 1506 MB | 121,830 | 0 |
| 学习通 | `com.chaoxing.mobile` | 7.0.4 | 248 MB | `64fd5211` | 2 | 558 | 0.31s | 251 MB | 380 | 0 |
| 淘宝 | `com.taobao.taobao` | 10.66.10 | 90 MB | `12525ac9` | 13 | 102,146 | 4.00s | 1146 MB | 72,150 | 0 |
| 同花顺 | `com.hexin.plat.android` | 11.62.03 | 198 MB | `20feb874` | 11 | 72,014 | 2.52s | 529 MB | 50,836 | 0 |
| 剪映 | `com.lemon.lv` | 21.5.0 | 438 MB | `39c03cf8` | 46 | 329,997 | 12.74s | 2856 MB | 272,324 | 0 |
| Weibo | `com.sina.weibo` | 16.9.1 | 226 MB | `20117d66` | 20 | 145,492 | 6.52s | 1192 MB | 98,347 | 0 |
| WeChat | `com.tencent.mm` | 8.0.78 | 268 MB | `846b4111` | 17 | 249,909 | 16.08s | 1346 MB | 239,599 | 0 |
| 小红书 | `com.xingin.xhs` | 8.84.5.5 | 112 MB | `418e60cc` | 14 | 170,579 | 4.98s | 714 MB | 116,844 | 0 |
| 星野 | `com.xingye.app` | 2.56.702 | 146 MB | `757cfe55` | 38 | 108,449 | 4.30s | 1127 MB | 74,591 | 0 |
| UU远程 | `com.netease.uuremote` | 4.40.0 | 25 MB | `de426ecb` | 2 | 18,419 | 1.18s | 375 MB | 17,139 | 0 |

## Subcommand battery

Thirteen subcommands, one timed run each per APK (all subsecond on
this machine). Query targets derive per APK: the package name for
`listclasses`/`strings`/`findrefs string`, `onCreate` for
`findrefs method`, the launcher class for `members`/`hierarchy`/
`disasm`/`getclass`. `†` marks the packed-APK launcher classes that
live outside the parsable dex.

| App | info | listclasses | manifest | mainactivity | res | largest | strings | findrefs-string | findrefs-method | members | hierarchy | disasm | getclass |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| 滴滴 | 0.04s | 0.03s | 0.00s | 0.03s | 0.00s | 0.11s | 0.04s | 0.03s | 0.03s | 0.03s | 0.03s | 0.03s | 0.14s |
| 高德地图 | 0.05s | 0.03s | 0.00s | 0.03s | 0.00s | 0.11s | 0.03s | 0.03s | 0.03s | 0.04s | 0.03s | 0.03s | 0.15s |
| 学信网 | 0.01s | 0.00s | 0.00s | 0.01s | 0.00s | 0.01s | 0.01s | 0.01s | 0.01s | 0.01s | 0.01s | 0.02s | 0.01s† |
| 中国移动 | 0.00s | 0.00s | 0.00s | 0.00s | 0.01s | 0.00s | 0.00s | 0.00s | 0.00s | 0.00s | 0.00s | 0.00s | 0.00s† |
| 招商银行 | 0.03s | 0.01s | 0.00s | 0.04s | 0.00s | 0.09s | 0.05s | 0.01s | 0.03s | 0.04s | 0.04s | 0.04s | 0.03s† |
| 智谱清言 | 0.02s | 0.02s | 0.01s | 0.02s | 0.00s | 0.06s | 0.02s | 0.02s | 0.03s | 0.02s | 0.02s | 0.02s | 0.06s |
| Minis | 0.02s | 0.01s | 0.00s | 0.01s | 0.00s | 0.02s | 0.02s | 0.02s | 0.02s | 0.02s | 0.02s | 0.02s | 0.02s |
| 网易云音乐 | 0.06s | 0.06s | 0.00s | 0.07s | 0.01s | 0.29s | 0.10s | 0.05s | 0.05s | 0.08s | 0.08s | 0.08s | 0.33s |
| Telegram | 0.03s | 0.03s | 0.00s | 0.03s | 0.00s | 0.05s | 0.03s | 0.03s | 0.04s | 0.03s | 0.03s | 0.04s | 0.42s |
| 京东 | 0.05s | 0.03s | 0.00s | 0.04s | 0.00s | 0.16s | 0.06s | 0.03s | 0.04s | 0.06s | 0.05s | 0.06s | 0.17s |
| WhatsApp | 0.04s | 0.01s | 0.00s | 0.05s | 0.01s | 0.13s | 0.07s | 0.04s | 0.04s | 0.05s | 0.05s | 0.05s | 0.13s |
| 支付宝 | 0.08s | 0.06s | 0.00s | 0.09s | 0.00s | 0.33s | 0.12s | 0.08s | 0.08s | 0.11s | 0.10s | 0.09s | 0.38s |
| AutoClaw | 0.03s | 0.02s | 0.00s | 0.02s | 0.00s | 0.04s | 0.02s | 0.02s | 0.03s | 0.02s | 0.02s | 0.02s | 0.04s |
| AutoGLM | 0.01s | 0.01s | 0.00s | 0.00s | 0.00s | 0.05s | 0.01s | 0.01s | 0.01s | 0.01s | 0.01s | 0.00s | 0.07s |
| 懂车帝 | 0.08s | 0.05s | 0.00s | 0.08s | 0.02s | 0.38s | 0.11s | 0.05s | 0.07s | 0.11s | 0.12s | 0.09s | 0.42s |
| 抖音 | 0.14s | 0.09s | 0.00s | 0.15s | 0.02s | 0.68s | 0.19s | 0.13s | 0.16s | 0.19s | 0.19s | 0.17s | 0.75s |
| 百度 | 0.05s | 0.04s | 0.01s | 0.07s | 0.06s | 0.28s | 0.09s | 0.05s | 0.06s | 0.08s | 0.08s | 0.07s | 0.31s |
| DeepSeek | 0.03s | 0.02s | 0.00s | 0.03s | 0.00s | 0.04s | 0.03s | 0.04s | 0.04s | 0.03s | 0.03s | 0.03s | 0.04s |
| 知乎 | 0.07s | 0.06s | 0.00s | 0.07s | 0.01s | 0.26s | 0.09s | 0.04s | 0.05s | 0.08s | 0.08s | 0.07s | 0.29s |
| Meituan | 0.05s | 0.02s | 0.00s | 0.05s | 0.01s | 0.19s | 0.07s | 0.04s | 0.05s | 0.06s | 0.08s | 0.06s | 0.22s |
| 哔哩哔哩 | 0.09s | 0.07s | 0.00s | 0.09s | 0.01s | 0.46s | 0.15s | 0.06s | 0.07s | 0.12s | 0.12s | 0.11s | 0.55s |
| Kimi | 0.03s | 0.02s | 0.00s | 0.02s | 0.00s | 0.05s | 0.03s | 0.04s | 0.04s | 0.03s | 0.02s | 0.04s | 0.05s |
| Lark | 0.09s | 0.05s | 0.00s | 0.11s | 0.01s | 0.42s | 0.18s | 0.04s | 0.07s | 0.13s | 0.14s | 0.12s | 0.52s |
| MiniMax | 0.02s | 0.02s | 0.00s | 0.03s | 0.00s | 0.07s | 0.04s | 0.01s | 0.02s | 0.04s | 0.03s | 0.03s | 0.06s |
| 拼多多 | 0.03s | 0.01s | 0.01s | 0.02s | 0.00s | 0.08s | 0.02s | 0.03s | 0.03s | 0.03s | 0.02s | 0.02s | 0.09s |
| Toutiao | 0.10s | 0.05s | 0.00s | 0.12s | 0.02s | 0.52s | 0.14s | 0.06s | 0.09s | 0.14s | 0.15s | 0.13s | 0.49s |
| 豆包 | 0.14s | 0.11s | 0.00s | 0.13s | 0.02s | 0.59s | 0.23s | 0.07s | 0.11s | 0.16s | 0.17s | 0.15s | 0.95s |
| QQ | 0.13s | 0.07s | 0.00s | 0.16s | 0.02s | 0.60s | 0.24s | 0.10s | 0.12s | 0.19s | 0.18s | 0.18s | 0.88s |
| Reqable | 0.01s | 0.01s | 0.00s | 0.01s | 0.00s | 0.02s | 0.01s | 0.02s | 0.02s | 0.01s | 0.01s | 0.01s | 0.02s |
| DingDing | 0.10s | 0.06s | 0.00s | 0.13s | 0.01s | 0.36s | 0.16s | 0.06s | 0.07s | 0.15s | 0.13s | 0.12s | 0.40s |
| 学习通 | 0.16s | 0.00s | 0.00s | 0.16s | 0.01s | 0.17s | 0.16s | 0.16s | 0.16s | 0.16s | 0.16s | 0.17s | 0.16s† |
| 淘宝 | 0.05s | 0.04s | 0.00s | 0.05s | 0.00s | 0.19s | 0.06s | 0.04s | 0.06s | 0.06s | 0.06s | 0.06s | 0.19s |
| 同花顺 | 0.04s | 0.02s | 0.00s | 0.04s | 0.01s | 0.14s | 0.05s | 0.03s | 0.03s | 0.06s | 0.05s | 0.04s | 0.04s† |
| 剪映 | 0.14s | 0.08s | 0.00s | 0.13s | 0.02s | 0.54s | 0.28s | 0.07s | 0.10s | 0.16s | 0.16s | 0.15s | 0.73s |
| Weibo | 0.06s | 0.05s | 0.00s | 0.07s | 0.02s | 0.28s | 0.11s | 0.06s | 0.06s | 0.09s | 0.08s | 0.08s | 0.30s |
| WeChat | 0.06s | 0.06s | 0.00s | 0.08s | 0.01s | 0.28s | 0.12s | 0.09s | 0.07s | 0.11s | 0.09s | 0.10s | 0.37s |
| 小红书 | 0.04s | 0.04s | 0.00s | 0.05s | 0.02s | 0.18s | 0.05s | 0.03s | 0.04s | 0.05s | 0.05s | 0.05s | 0.23s |
| 星野 | 0.06s | 0.03s | 0.02s | 0.07s | 0.00s | 0.22s | 0.12s | 0.03s | 0.04s | 0.12s | 0.09s | 0.08s | 0.19s |
| UU远程 | 0.02s | 0.02s | 0.00s | 0.02s | 0.00s | 0.04s | 0.02s | 0.02s | 0.03s | 0.02s | 0.02s | 0.02s | 0.04s |

## Notes

- **Packed APKs**: CHSI and CM10086 carry 4-7 classes, UU remote
  and Chaoxing a few hundred — the shell dex holds only the loader (real
  code lives in the encrypted payload, itself useful intel). Zhihu's and
  CMB's launcher classes are outside the parsable dex (`getclass` returns
  a clear not-found; every other subcommand works).
- **Pathological timeouts**: 0-2 R8 monster-method classes per APK
  (gson adapters, the SendMessagesHelper family) degrade via the
  deadline mechanism — that class is dropped, everything else emits
  completely. Documented design (monitored threads, 1.5s/method
  deadline), not a crash.
- **Fake dex skip**: UU remote's `assets/39285EFA.dex` is an encrypted
  payload with a non-DEX magic — skipped with a notice; the 17,139 real
  classes decompile normally.

