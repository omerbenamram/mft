# Performance theses (living document)

This file is a running log of **hypotheses (“theses”)** and the **measurement protocol** we’ll use to validate them one by one.

Principles:
- **One change per experiment** (or one tightly-coupled set), with before/after measurements.
- Prefer **end-to-end CLI throughput** on a fixed input (`samples/MFT`) as the primary KPI.
- Keep a **saved profile** around for every “checkpoint” so we can explain wins / regressions.
- When results are noisy, prefer **median** and **min** over mean, and record variance.

## Canonical workloads

All commands assume:

```bash
cargo build --release --bin mft_dump
```

- **W1 (JSONL, end-to-end)**:

```bash
./target/release/mft_dump samples/MFT -o jsonl -f /dev/null --no-confirm-overwrite
```

- **W2 (CSV, end-to-end)**:

```bash
./target/release/mft_dump samples/MFT -o csv -f /dev/null --no-confirm-overwrite
```

## Baseline environment (2025-12-23)

- **OS**: macOS 26.2 (25C56), Darwin 25.2.0, arm64
- **HW**: `Mac15,6`, 11 cores, 36GB RAM
- **Toolchain**: rustc 1.92.0, cargo 1.92.0

If you’re re-running baselines on a different machine/OS, append a new baseline section rather than overwriting this one.

## Baseline numbers (2025-12-23)

Measured with `hyperfine` (30 runs, 3 warmup), output to `/dev/null`:

- **W1 JSONL**: ~**103 ms mean** (σ ~14 ms), range ~94–169 ms
- **W2 CSV**: observed **high variance** on this machine/session (outliers up to ~468 ms). Re-run on a quiet system before treating CSV as a stable KPI.

Raw captures (not committed, under `target/`):
- `target/perf-baseline.json`
- `target/perf-baseline.csv.json`

## Profiling (baseline)

### Samply (hot functions / leafs)

End-to-end JSONL profile (merge many iterations for stability):

```bash
mkdir -p target/samply
samply record --save-only --unstable-presymbolicate --reuse-threads --main-thread-only \
  -o target/samply/mft_dump_jsonl_merged.profile.json.gz \
  --iteration-count 200 -- \
  ./target/release/mft_dump samples/MFT -o jsonl -f /dev/null --no-confirm-overwrite

samply load target/samply/mft_dump_jsonl_merged.profile.json.gz
```

What to look at:
- **Call Tree + “Invert call stack”** for top leaf frames (true hot spots).
- **Call Tree (non-inverted)** for inclusive costs (big buckets like “serialization”).
- Filter stack: `mft::` / `mft_dump::` to focus on crate code.

#### Baseline profile notes (from `mft_dump_jsonl_merged`)

Top inclusive buckets:
- `MftEntry::serialize` dominates (serialization is the main cost center).
- `MftParser::get_entry` is non-trivial but secondary in the end-to-end JSONL path.

Top leaf frames include:
- `serde_json::ser::format_escaped_str_contents` (string escaping)
- `_platform_memmove` (buffer copying)
- `write` / `read` / `__lseek` (I/O syscalls)

### macOS hardware counters (optional)

On macOS, `xctrace` can record CPU counter templates. This isn’t as clean as Linux `perf stat`, but it can still provide useful sanity checks (e.g. cycle counts / bottleneck breakdown).

Record:

```bash
mkdir -p target/xctrace
xcrun xctrace record --no-prompt --template 'CPU Counters' \
  --output target/xctrace/mft_dump_jsonl_cpu_counters.trace \
  --launch -- ./target/release/mft_dump samples/MFT -o jsonl -f /dev/null --no-confirm-overwrite
```

Explore/export:

```bash
xcrun xctrace export --input target/xctrace/mft_dump_jsonl_cpu_counters.trace --toc
```

We’ve confirmed these schemas exist in the trace:
- `MetricTable`
- `MetricAggregationForProcess`
- `CounterMetricAggregatedForProcess`

Note: the default templates we tried expose cycles + “bottleneck” style metrics; raw retired-instruction counts may require different counter configuration (or use Linux `perf stat`).

## Theses / hypotheses backlog

Each item includes:
- **Claim**: what we think is true
- **Change**: the minimal code change to test it
- **Success metric**: what improvement we require on W1
- **Guardrails**: correctness + “don’t regress too much” constraints

### H1 — Remove per-entry allocation/copy in JSON serialization

- **Claim**: end-to-end JSONL is dominated by `serde_json` work; we can shave a large chunk by removing avoidable allocations/copies.
- **Evidence**: `MftEntry::serialize` is ~3/4 of inclusive time in samply; leaf frames show `memmove` and string escaping.
- **Change**:
  - Stop building a `Vec<MftAttribute>` inside `MftEntry::serialize` (stream attributes as a `SerializeSeq`).
  - Stop serializing into a fresh `Vec<u8>` per entry in `mft_dump::print_json_entry` (reuse a buffer).
  - Use a faster serde-compatible JSON serializer for JSONL (`sonic-rs`).
- **Success metric**: W1 improves by **≥ 15%** on median time.
- **Guardrails**:
  - Output must remain **semantically identical** for JSONL (same JSON values per line; formatting/escaping differences are allowed).
  - `cargo test --all-features` stays green.

### H2 — Reduce syscall overhead in sequential reads

- **Claim**: sequential iteration still pays a lot of `lseek` overhead; removing it will meaningfully reduce CPU time once serialization is cheaper.
- **Evidence**: parser-only profiles show `__lseek` as a major leaf; end-to-end still has visible syscall leaf time.
- **Change**:
  - Teach `get_entry` to skip `seek` when already positioned for sequential reads (track `next_read_offset`).
  - Update CLI loop to use the sequential path when ranges are not random.
- **Success metric**: W1 improves by **≥ 5%** after H1 lands (or measure on W2 if JSONL still hides it).
- **Guardrails**: no functional changes; still supports `--ranges`.

### H3 — Reduce timestamp formatting overhead (post-H1)

- **Claim**: `chrono` formatting shows up noticeably; swapping to a faster formatting path could help.
- **Evidence**: `chrono` formatting appears among hot inclusive nodes in JSONL profile.
- **Change**: investigate faster RFC3339 formatting and/or reduce intermediate allocations.
- **Success metric**: W1 improves by **≥ 5%** (only worth doing if H1/H2 make this visible).

## Completed optimizations

### H1 (2025-12-23) — Faster JSONL serialization

**What changed**
- Stream `attributes` in `MftEntry` serialization (avoid allocating `Vec<MftAttribute>`).
- Reuse a `Vec<u8>` JSON buffer in `mft_dump` (avoid per-entry allocation).
- Switch JSONL output from `serde_json` to **`sonic-rs`** (serde-compatible, SIMD-focused).
  - Pretty JSON (`-o json`) still uses `serde_json` for formatting.

**Benchmarks**

Single `hyperfine` run comparing the saved binaries:

```bash
hyperfine --warmup 3 --runs 30 \
  './target/release/mft_dump.h1_before samples/MFT -o jsonl -f /dev/null --no-confirm-overwrite' \
  './target/release/mft_dump.h1_after3_sonic samples/MFT -o jsonl -f /dev/null --no-confirm-overwrite'
```

Extracted medians (from `target/h1-before-vs-after.hyperfine.json`):
- **Before median**: **95.94 ms**
- **After median**: **73.65 ms**
- **Speedup**: ~**1.30×** (≈ **23%** faster)

**Profile delta (top leaf)**
- **Before**: `serde_json::ser::format_escaped_str_contents` (~18% self)
- **After**: `sonic_rs::format::Formatter::write_string_fast` (~18% self)

Profiles:
- `target/samply/h1_before.profile.json.gz`
- `target/samply/h1_after3_sonic.profile.json.gz`

**Correctness check**

We verified **semantic equality** of JSONL output on a small range:
- Command: both binaries with `--ranges 0-200` and `-o jsonl`
- Method: parse each line as JSON and compare Python objects
- Result: OK (193 lines; some entries are skipped due to zero headers)

### H2 (2025-12-23) — Skip per-entry seek for sequential scans

**What changed**
- `MftParser::get_entry` now tracks the **next expected stream offset** and only calls `seek()` when the requested entry is not the sequential next entry.

**Benchmarks**

Single `hyperfine` run comparing the saved binaries:

```bash
hyperfine --warmup 3 --runs 30 \
  './target/release/mft_dump.h2_before samples/MFT -o jsonl -f /dev/null --no-confirm-overwrite' \
  './target/release/mft_dump.h2_after samples/MFT -o jsonl -f /dev/null --no-confirm-overwrite'
```

Extracted medians (from `target/h2-before-vs-after.hyperfine.json`):
- **Before median**: **74.72 ms**
- **After median**: **63.06 ms**
- **Speedup**: ~**1.18×** (≈ **16%** faster)

**Profile delta (leaf reduction)**

Before (`target/samply/h2_before.profile.json.gz`, inverted call tree):
- `read` ~11% self
- `__lseek` ~5.5% self

After (`target/samply/h2_after.profile.json.gz`, inverted call tree):
- `read` ~4.8% self
- `__lseek` no longer appears in top leaf list (effectively eliminated for W1)


