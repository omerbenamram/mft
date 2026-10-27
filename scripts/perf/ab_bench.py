#!/usr/bin/env python3
"""Interleaved A/B wall-clock benchmark for `mft_dump` binaries.

Runs every binary once per round, alternating the order each round, so slow drift on a noisy
machine (shared CI/VM hosts, thermal throttling) affects all binaries equally. Reports the median
and the minimum wall time; on noisy hosts the minimum is the more stable statistic.

usage: scripts/perf/ab_bench.py [--runs N] [--format jsonl|json|csv] [--input samples/MFT] BIN...
"""
import argparse
import os
import resource
import statistics
import subprocess
import time


def run_once(binary, input_path, fmt):
    start = time.perf_counter()
    before = resource.getrusage(resource.RUSAGE_CHILDREN)
    subprocess.run(
        [binary, input_path, "-o", fmt, "-f", os.devnull, "--no-confirm-overwrite"],
        check=True,
    )
    after = resource.getrusage(resource.RUSAGE_CHILDREN)
    cpu = (after.ru_utime - before.ru_utime) + (after.ru_stime - before.ru_stime)
    return time.perf_counter() - start, cpu


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--runs", type=int, default=30)
    parser.add_argument("--format", default="jsonl", choices=["jsonl", "json", "csv"])
    parser.add_argument("--input", default="samples/MFT")
    parser.add_argument("binaries", nargs="+")
    args = parser.parse_args()

    results = {b: [] for b in args.binaries}
    for b in args.binaries:  # warmup (page cache, binary loading)
        run_once(b, args.input, args.format)
    for i in range(args.runs):
        order = args.binaries if i % 2 == 0 else args.binaries[::-1]
        for b in order:
            results[b].append(run_once(b, args.input, args.format))

    baseline = None
    for b in args.binaries:
        wall = [w for w, _ in results[b]]
        cpu = [c for _, c in results[b]]
        median, minimum = statistics.median(wall), min(wall)
        line = (
            f"{b:40} {args.format:5} wall median {median * 1e3:8.1f} ms"
            f"  min {minimum * 1e3:8.1f} ms  cpu median {statistics.median(cpu) * 1e3:8.1f} ms"
        )
        if baseline is None:
            baseline = (median, minimum)
        else:
            line += f"  | vs first: median {baseline[0] / median:.3f}x  min {baseline[1] / minimum:.3f}x"
        print(line)


if __name__ == "__main__":
    main()
