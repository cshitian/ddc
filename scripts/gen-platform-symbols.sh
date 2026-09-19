#!/bin/zsh
# Regenerate the built-in platform symbol table (the IntDef/LongDef
# domain blob embedded in ddc-cli as platform_symbols.bin.gz, raw
# DEFLATE — ddc's inflater is raw, not zlib-wrapped).
#
#   scripts/gen-platform-symbols.sh [sdk-platform-dir]
#
# Default: the newest platform under ~/Library/Android/sdk (or
# $ANDROID_HOME). The blob is version-independent in effect: domains
# are exact-match, so methods missing from the chosen API level simply
# stay numeric. Commit the regenerated blob.
set -euo pipefail

DDC=target/release/ddc
SDK=${1:-${ANDROID_HOME:-$HOME/Library/Android/sdk}/platforms}
platform=$(ls -d "$SDK"/android-* 2>/dev/null | sort -V | tail -1)
[[ -n $platform ]] || { echo "no SDK platforms under $SDK" >&2; exit 1; }

cargo build --release --quiet
tmp=$(mktemp)
$DDC --symbols "$platform" --symbols-out "$tmp" -V >/dev/null 2>&1
python3 - "$tmp" crates/ddc-cli/src/platform_symbols.bin.gz <<'PY'
import sys, zlib
raw = open(sys.argv[1], 'rb').read()
co = zlib.compressobj(9, zlib.DEFLATED, -15)  # RAW deflate
gz = co.compress(raw) + co.flush()
open(sys.argv[2], 'wb').write(gz)
print(f"platform symbols: {len(raw)} bytes raw -> {len(gz)} deflated")
PY
rm -f "$tmp"
echo "blob: crates/ddc-cli/src/platform_symbols.bin.gz — commit it"
