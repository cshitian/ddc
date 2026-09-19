#!/bin/zsh
# Regenerate the built-in platform symbol table. The repo keeps the
# READABLE form (crates/ddc-cli/src/platform_symbols.txt — one domain
# per line); build.rs compresses it into the binary at compile time.
#
#   scripts/gen-platform-symbols.sh [sdk-platform-dir]
#
# Default: the newest platform under ~/Library/Android/sdk (or
# $ANDROID_HOME). The table is exact-match, so methods missing from
# the chosen API level simply stay numeric. Commit the regenerated
# .txt — the binary blob is no longer checked in.
set -euo pipefail

DDC=target/release/ddc
SDK=${1:-${ANDROID_HOME:-$HOME/Library/Android/sdk}/platforms}
platform=$(ls -d "$SDK"/android-* 2>/dev/null | sort -V | tail -1)
[[ -n $platform ]] || { echo "no SDK platforms under $SDK" >&2; exit 1; }

cargo build --release --quiet
$DDC --symbols "$platform" --symbols-out crates/ddc-cli/src/platform_symbols.txt -V >/dev/null 2>&1
echo "blob: crates/ddc-cli/src/platform_symbols.txt — commit it (build.rs compresses)"
