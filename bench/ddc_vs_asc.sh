#!/bin/bash
# ddc vs ASC progressive-analysis benchmark.
set -u
DDC=/Users/e/Documents/project/ddc/target/release/ddc
ASC=/Users/e/Documents/github/ASC
PY=$ASC/.venv/bin/python3
DL=/Users/e/Downloads

run_ddc() { /usr/bin/time -p "$DDC" "$@" >/dev/null 2>/tmp/ddc-t.txt; grep '^real' /tmp/ddc-t.txt | awk '{print $2}'; }
run_asc() { (cd "$ASC" && timeout 300 /usr/bin/time -p "$PY" main.py "$@" >/dev/null 2>/tmp/asc-t.txt); grep '^real' /tmp/asc-t.txt | awk '{print $2}'; }

median3() { printf '%s\n' "$@" | sort -g | sed -n '2p'; }

apkb() {
  case "$1" in
    lark) echo "$DL/lark_feishu_website_organic_and_v6667_8000250_a44c_1789402075.apk" ;;
    weixin) echo "$DL/weixin8078android3180_0x28004e32_arm64.apk" ;;
    whatsapp) echo "$DL/WhatsApp.apk" ;;
    telegram) echo "$DL/Telegram.apk" ;;
    weibo) echo "$DL/weibo_16.9.1_vcode_8166_wm_3333_1001_so_32_64_weibo_10066_232871.apk" ;;
  esac
}
classb() {
  case "$1" in
    lark) echo "com.ss.android.lark.MessageTenantConfTask" ;;
    weixin) echo "com.tencent.mm.BuildConfig" ;;
    whatsapp) echo "com.whatsapp.AppShell" ;;
    telegram) echo "org.telegram.messenger.ApplicationLoader" ;;
    weibo) echo "com.sina.weibo.WeiboApplication" ;;
  esac
}

for key in lark weixin whatsapp telegram weibo; do
  apk=$(apkb "$key")
  cls=$(classb "$key")
  for query in string type method getclass; do
    d1=""; d2=""; d3=""; a1=""; a2=""; a3=""
    case $query in
      string)
        for r in 1 2 3; do
          eval "d$r=\$(run_ddc findrefs \"$apk\" string token)"
          eval "a$r=\$(run_asc findrefs \"$apk\" string token)"
        done ;;
      type)
        for r in 1 2 3; do
          eval "d$r=\$(run_ddc findrefs \"$apk\" type android/app/Activity)"
          eval "a$r=\$(run_asc findrefs \"$apk\" type android/app/Activity)"
        done ;;
      method)
        for r in 1 2 3; do
          eval "d$r=\$(run_ddc findrefs \"$apk\" method onCreate --class android/app/Activity)"
          eval "a$r=\$(run_asc findrefs \"$apk\" method onCreate --class android/app/Activity)"
        done ;;
      getclass)
        for r in 1 2 3; do
          eval "d$r=\$(run_ddc getclass \"$apk\" \"$cls\")"
          eval "a$r=\$(run_asc getclass \"$apk\" \"$cls\")"
        done ;;
    esac
    dm=$(median3 "$d1" "$d2" "$d3")
    am=$(median3 "$a1" "$a2" "$a3")
    echo "RESULT $key $query ddc=$dm asc=$am"
  done
done
echo "BENCH DONE"
