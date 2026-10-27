#!/bin/bash
# Byte-compares the full output (stdout file + stderr) of two `mft_dump` binaries in every
# output format. Use it to prove that a performance change does not change output.
#
# usage: scripts/perf/check_identical.sh BEFORE_BIN AFTER_BIN [INPUT]
set -euo pipefail

BEFORE=$1
AFTER=$2
INPUT=${3:-samples/MFT}
OUT=$(mktemp -d)
trap 'rm -rf "$OUT"' EXIT

status=0
for format in jsonl json csv bodyfile; do
    "$BEFORE" "$INPUT" -o "$format" -f "$OUT/before.$format" --no-confirm-overwrite 2>"$OUT/before.$format.err" || true
    "$AFTER" "$INPUT" -o "$format" -f "$OUT/after.$format" --no-confirm-overwrite 2>"$OUT/after.$format.err" || true
    if cmp -s "$OUT/before.$format" "$OUT/after.$format" &&
        cmp -s "$OUT/before.$format.err" "$OUT/after.$format.err"; then
        echo "$format: byte-identical ($(wc -c <"$OUT/after.$format") bytes)"
    else
        echo "$format: DIFFERENT"
        status=1
    fi
done
exit $status
