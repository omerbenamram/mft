#!/bin/bash
# Deterministic instruction counts (valgrind/cachegrind, no cache simulation) for `mft_dump`
# binaries. Unlike wall time this is reproducible to <0.1% even on noisy machines, so it is the
# best signal for small changes. It does not see syscalls or memory stalls; pair it with
# scripts/perf/ab_bench.py.
#
# usage: scripts/perf/instructions.sh [-f jsonl|json|csv] [-i samples/MFT] BIN...
set -euo pipefail

FORMAT=jsonl
INPUT=samples/MFT
while getopts "f:i:" opt; do
    case $opt in
    f) FORMAT=$OPTARG ;;
    i) INPUT=$OPTARG ;;
    *) exit 2 ;;
    esac
done
shift $((OPTIND - 1))

for bin in "$@"; do
    count=$(valgrind --tool=cachegrind --cache-sim=no --cachegrind-out-file=/dev/null \
        "$bin" "$INPUT" -o "$FORMAT" -f /dev/null --no-confirm-overwrite 2>&1 |
        awk '/I *refs/ {gsub(",", "", $NF); print $NF}')
    printf "%-40s %-5s %15s instructions\n" "$bin" "$FORMAT" "$count"
done
