#!/bin/zsh
# README performance table: full decompile + every query subcommand,
# 3 runs each (arithmetic mean), wall time + peak RSS via
# /usr/bin/time -l (RSS in BYTES). Strictly serial — one command at a
# time; concurrent full runs once swap-crashed this machine.

set -u
DDC=${DDC:-$PWD/../target/release/ddc}
OUT=${OUT:-/tmp/ddc-bench-out}
RESULTS=${RESULTS:-$PWD/perf_table.tsv}

typeset -a NAMES PATHS
NAMES=(lark Telegram qq weixin WhatsApp weibo reqable)
PATHS=(
  /Users/e/Downloads/lark-android-8.0.2-ad291240bca78a97a60a4d4ab9f57b96.apk
  /Users/e/Downloads/Telegram.apk
  /Users/e/Downloads/qq_9.3.65_2a98ecf55b5ee03a.apk
  /Users/e/Downloads/weixin8078android3180_0x28004e32_arm64.apk
  /Users/e/Downloads/WhatsApp.apk
  /Users/e/Downloads/weibo_16.9.1_vcode_8166_wm_3333_1001_so_32_64_weibo_10066_232871.apk
  /Users/e/Downloads/reqable-app-android-arm64.apk
)

: > "$RESULTS"

# one run: prints "seconds bytes"
timed() {
  /usr/bin/time -l timeout 300 "$@" > /dev/null 2> /tmp/ddc-bench.time
  local real rss
  real=$(awk '/ real/ {print $1; exit}' /tmp/ddc-bench.time)
  rss=$(awk '/maximum resident/ {print $1; exit}' /tmp/ddc-bench.time)
  [[ -n "$real" ]] || real=0
  [[ -n "$rss" ]] || rss=0
  echo "$real $rss"
}

# mean of 3: prints "seconds mb"
mean3() {
  local cmd=("$@")
  local t1 t2 t3 r1 r2 r3
  read t1 r1 <<< "$(timed "${cmd[@]}")"
  read t2 r2 <<< "$(timed "${cmd[@]}")"
  read t3 r3 <<< "$(timed "${cmd[@]}")"
  python3 -c "print(f'{($t1+$t2+$t3)/3:.2f} {max($r1,$r2,$r3)/1048576:.0f}')"
}

typeset -i i
for ((i = 1; i <= ${#NAMES}; i++)); do
  n=$NAMES[i]; apk=$PATHS[i]
  size=$(stat -f %z "$apk")
  echo "== $n ($(python3 -c "print(f'{$size/1048576:.0f}')")MB)" >&2

  # per-APK probe targets: package string + launcher class
  pkg=$($DDC mainactivity "$apk" 2>/dev/null | awk '/^package/ {print $2}')
  cls=$($DDC mainactivity "$apk" 2>/dev/null | awk '/^launcher/ {print $2}')
  [[ -n "$cls" ]] || cls=$($DDC listclasses "$apk" 2>/dev/null | sed -n 2p | awk '{print $1}')
  echo "   pkg=$pkg cls=$cls" >&2

  rm -rf "$OUT"

  echo -n "$n	$size	full" >> "$RESULTS"
  echo "	$(mean3 $DDC "$apk" -o $OUT)" >> "$RESULTS"

  for spec in \
    "info|$DDC info $apk" \
    "listclasses|$DDC listclasses $apk" \
    "manifest|$DDC manifest $apk" \
    "mainactivity|$DDC mainactivity $apk" \
    "res|$DDC res $apk" \
    "largest|$DDC largest $apk -n 10" \
    "strings|$DDC strings $apk -f $pkg --with-locations" \
    "findrefs-string|$DDC findrefs $apk string $pkg" \
    "findrefs-method|$DDC findrefs $apk method onCreate" \
    "members|$DDC members $apk --method onCreate" \
    "hierarchy|$DDC hierarchy $apk $cls" \
    "disasm|$DDC disasm $apk $cls" \
    "getclass|$DDC getclass $apk $cls"
  do
    label=${spec%%|*}
    cmd=${spec#*|}
    echo -n "$n	$size	$label" >> "$RESULTS"
    echo "	$(mean3 ${(z)cmd})" >> "$RESULTS"
  done
  echo "   done" >&2
done
echo "wrote $RESULTS" >&2
