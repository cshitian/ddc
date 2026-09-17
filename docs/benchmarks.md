# Benchmarks

[English] | [简体中文](zh-CN/benchmarks.md)

All numbers from the author's machine (Apple Silicon, 6P+12E cores),
median of runs, release profile with `target-cpu=native`. Scripts and raw
results live in [`bench/`](../bench/) (`DDC`/`DL`/`ASC`/`RASC` environment
variables override the paths).

## Full decompile

Seven real-world APKs — reqable 3.2.23 (34MB), Telegram (62MB), WhatsApp
(139MB), weibo 16.9.1 (226MB, 20 dex), weixin 8.0.78 (268MB), lark 8.0.2
(398MB, 59 dex), qq 9.3.65 (374MB) — 3-run averages of wall time, peak
RSS via `/usr/bin/time -l`:

| APK | Size | Full decompile | Peak RSS |
|---|---|---|---|
| reqable | 34 MB | **0.27s** | 147 MB |
| Telegram | 62 MB | **8.09s** | 1016 MB |
| WhatsApp | 139 MB | **8.67s** | 1197 MB |
| weibo | 226 MB | **6.13s** | 1238 MB |
| weixin | 268 MB | **10.15s** | 1413 MB |
| lark | 398 MB | **6.08s** | 1580 MB |
| qq | 374 MB | **17.85s** | 2330 MB |

## Every query subcommand, same seven APKs

3-run averages; cells are wall time / peak RSS. Query targets:
`strings -f <package> --with-locations`; `findrefs string <package>`;
`findrefs method onCreate`; `hierarchy`/`disasm`/`getclass` use each
app's launcher class (Telegram's `LaunchActivity` is an exceptionally
large class):

| Command | reqable | Telegram | WhatsApp | weibo | weixin | lark | qq |
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

Raw numbers and the harness: [`bench/perf_table.sh`](../bench/perf_table.sh)
(strictly serial; concurrent full runs once swap-crashed the machine).

## Methodology notes

- **Serial, 3-round medians.** Same-machine variance reaches ±25% (E-core
  scheduling + memory bandwidth contention); a single run proves nothing.
- **`/usr/bin/time`'s user time includes all threads** — a "busy" worker
  is not CPU (write-back-pressured threads tick wall time without cycles).
  Look at user+sys ÷ effective cores vs wall; the gap is scheduling/blocking.
- **Wall-clock critical paths migrate**: first CPU, then disk writes, then
  deadline idling on timed-out classes. Re-profile every round; don't keep
  optimizing the old hotspot.
- `DDC_PHASES=1` (phase timings, cumulative — difference them) and
  `DDC_BUCKETS=1` (per-class by block count) answer "which methods eat
  CPU" more directly than stack sampling; `sample <pid> 3 -file` early and
  late (different phases, different hotspots) when you need line-level
  attribution. RSS curves via `ps -o rss= -p $PID` every 5s locate the
  allocation phase (lark: 733MB at t=5s → 2086MB at t=10s = materialize
  peak, before any retirement fires). `/usr/bin/time -l` reports RSS in
  **bytes, not KB**.

## vs. ASC (earlier APK snapshot, same machine, alternating 3-round medians)

Five real APKs (62–353 MB), progressive queries, stdout discarded;
correctness cross-checked: 107/107 hits coincide:

| Query | ddc | ASC | Ratio |
|---|---|---|---|
| findrefs string (lark 353MB) | **0.32s** | 0.61s | 1.9× |
| findrefs string (weixin 268MB) | **0.22s** | 0.52s | 2.4× |
| findrefs string (weibo 226MB) | **0.19s** | 0.44s | 2.3× |
| findrefs type/method (all five) | **0.09–0.31s** | 0.29–0.66s | 2–3× |
| getclass (lark/weixin/weibo) | 0.18–0.42s | **0.10–0.12s** | ASC wins |
| getclass (Telegram, big class) | **0.05s** | 0.11s | ddc wins |
| findrefs memory (lark) | ~820MB | ~170MB | ASC leaner |

The getclass split: ASC bit-stream-probes the zip to inflate only the
target dex (a lower floor on huge multi-dex APKs); ddc parses all image
headers (~0.2s floor) then materializes lazily — it overtakes when the
class itself is expensive, loses to the floor when it isn't. On findrefs
scan domains ddc is uniformly faster (pipeline: parse waves → bounded
channel → scan threads consume-and-drop; `Arc`-shared APK bytes eliminate
compression copies).
