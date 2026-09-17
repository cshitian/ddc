# Benchmarks

[English] | [简体中文](zh-CN/benchmarks.md)

All numbers from the author's machine (Apple Silicon, 6P+12E cores),
median of runs, release profile with `target-cpu=native`. Scripts and raw
results live in [`bench/`](../bench/) (`DDC`/`DL`/`ASC`/`RASC` environment
variables override the paths).

## Full decompile

| APK | Classes | Result | Time | Peak RSS |
|---|---|---|---|---|
| reqable 34MB | 8,201 | 5,579/5,579 units, 0 failed | **0.21s** | 124MB |
| weibo 226MB, 20 dex | 145,492 | 98,348/98,349 (1 pathological gson class times out) | **5.4s** | 1.2GB |
| weixin 268MB | ~250k | 207,338 units | **9.0s** | 1.3GB |
| lark/Feishu 353MB, 59 dex | 567k | 208,702 units | **9.2s** | 2.2GB |
| WhatsApp 139MB | 42,273 units | | **7.5s** | 1.2GB |
| Telegram 62MB | 19,282 | 19,282/19,282 | **7.6s** | 975MB |

"Units" = compilation units written (a class with nested classes emits one
file for the family plus files for anonymous/local/lambda classes).

## Progressive queries

3-round medians, serial, machine otherwise idle:

| APK | findrefs hit | findrefs miss | listclasses | getclass | manifest | info |
|---|---|---|---|---|---|---|
| reqable 34MB | 0.01s | 0.01s | 0.01s | 0.01s | ~0 | 0.01s |
| Telegram 62MB | 0.04s | 0.02s | 0.03s | 0.04s | ~0 | 0.03s |
| WhatsApp 139MB | 0.03s | 0.01s | 0.05s | 0.07s | ~0 | 0.03s |
| weibo 226MB | 0.04s | 0.03s | 0.09s | 0.14s | ~0 | 0.04s |
| weixin 268MB | 0.05s | 0.04s | 0.14s | 0.19s | ~0 | 0.05s |
| lark 353MB | 0.07s | 0.03s | 0.20s | 0.35s | ~0 | 0.09s |

Browse subcommands (strings/members/hierarchy/largest/disasm/mainactivity/
res) run in 0.01–0.06s on these APKs; `pkg` decompiles a whole package
(Telegram's `org.telegram.tgnet`, 1561 classes, in 0.165s).

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

## vs. ASC (same machine, alternating 3-round medians)

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
