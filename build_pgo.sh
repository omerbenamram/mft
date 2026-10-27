#!/bin/bash
# Builds a profile-guided-optimized `mft_dump`.
#
# Requires `llvm-profdata` on PATH, matching rustc's LLVM version, e.g.:
#   rustup component add llvm-tools
#   export PATH="$(rustc --print sysroot)/lib/rustlib/$(rustc -vV | sed -n 's/host: //p')/bin:$PATH"
set -euo pipefail

get_default_target() {
    case "$(uname -sm)" in
    "Darwin x86_64") echo "x86_64-apple-darwin" ;;
    "Darwin arm64") echo "aarch64-apple-darwin" ;;
    "Linux x86_64") echo "x86_64-unknown-linux-gnu" ;;
    "Linux aarch64") echo "aarch64-unknown-linux-gnu" ;;
    *) echo "unknown" ;;
    esac
}

TARGET=${TARGET:-$(get_default_target)}
if [ "$TARGET" = "unknown" ]; then
    echo "Error: Unable to determine default target. Please specify TARGET explicitly."
    exit 1
fi

PGO_DATA_DIR=${PGO_DATA_DIR:-/tmp/mft-pgo-data}
BIN="./target/$TARGET/release/mft_dump"

echo "Using target: $TARGET"
echo "Using llvm-profdata at: $(which llvm-profdata) ($(llvm-profdata --version | head -2 | tail -1))"

echo "Cleaning up previous profile data"
rm -rf "$PGO_DATA_DIR"

echo "Building instrumented binary"
RUSTFLAGS="-Cprofile-generate=$PGO_DATA_DIR" \
    cargo build --release --bin mft_dump --target "$TARGET"

echo "Running instrumented binary"
for format in jsonl json csv bodyfile; do
    "$BIN" samples/MFT -o "$format" -f /dev/null --no-confirm-overwrite
done

echo "Merging profile data"
llvm-profdata merge -o "$PGO_DATA_DIR/merged.profdata" "$PGO_DATA_DIR"

echo "Building binary with profile data"
RUSTFLAGS="-Cprofile-use=$PGO_DATA_DIR/merged.profdata" \
    cargo build --release --bin mft_dump --target "$TARGET"

echo "PGO-optimized binary written to: $BIN"
