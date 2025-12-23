# Performance theses (living document)

This file is a running log of **hypotheses (“theses”)** and the **measurement protocol** we’ll use to validate them one by one.

Principles:
- **One change per experiment** (or one tightly-coupled set), with before/after measurements.
- Prefer **end-to-end CLI throughput** on a fixed input (`samples/MFT`) as the primary KPI.
- Keep a **saved profile** around for every “checkpoint” so we can explain wins / regressions.
- When results are noisy, prefer **median** and **min** over mean, and record variance.

## Agent playbook (reproducible workflow)

This section is the **exact workflow** used to land each hypothesis as a PR-quality change.
If you hand this file to another agent, they should be able to reproduce the same process and artifacts.

### Naming & artifacts (do this consistently)

Pick the next hypothesis ID: `H{N}` (monotonic, don’t reuse IDs).

- **Branch**: `perf/h{N}-{short-slug}` (example: `perf/h6-resident-slices`)
- **Saved binaries** (so benchmarks are stable and diffable):
  - `target/release/mft_dump.h{N}_before`
  - `target/release/mft_dump.h{N}_after`
- **Hyperfine JSON**:
  - `target/h{N}-before-vs-after.hyperfine.json`
- **Samply profiles** (merged by running many iterations):
  - `target/samply/h{N}_before.profile.json.gz`
  - `target/samply/h{N}_after.profile.json.gz`

### Canonical benchmark command lines (copy/paste)

These are the commands we benchmark/profiler-record. Keep them unchanged unless the thesis *requires* changing them.

W1 (JSONL, end-to-end, write suppressed):

```bash
./target/release/mft_dump samples/MFT -o jsonl -f /dev/null --no-confirm-overwrite
```

W2 (CSV, end-to-end, write suppressed):

```bash
./target/release/mft_dump samples/MFT -o csv -f /dev/null --no-confirm-overwrite
```

### Step-by-step: run an experiment end-to-end

#### 0) Start a new thesis

```bash
cd /Users/omerba/Workspace/mft
git checkout -b perf/h{N}-{short-slug}
```

#### 1) Build + snapshot the **before** binary

```bash
cd /Users/omerba/Workspace/mft
cargo build --release --bin mft_dump
cp -f target/release/mft_dump target/release/mft_dump.h{N}_before
```

#### 2) Record a stable **before** profile (Samply)

We merge many iterations so leaf frames are stable.

```bash
cd /Users/omerba/Workspace/mft
mkdir -p target/samply
samply record --save-only --unstable-presymbolicate --reuse-threads --main-thread-only \
  -o target/samply/h{N}_before.profile.json.gz \
  --iteration-count 200 -- \
  ./target/release/mft_dump.h{N}_before samples/MFT -o jsonl -f /dev/null --no-confirm-overwrite
```

To view (serve locally and open the printed Firefox Profiler URL):

```bash
cd /Users/omerba/Workspace/mft
samply load --no-open -P 4033 target/samply/h{N}_before.profile.json.gz
```

What to record from the UI:
- Use **Call Tree** + **Invert call stack** for top **leaf/self** frames.
- Use normal Call Tree for “big buckets” (inclusive time).
- Filter stack for `mft::` / `mft_dump::` when looking for in-crate work.

#### 3) Implement the change (keep it tight)

- Make the smallest change that tests the hypothesis.
- If you find yourself changing 5+ unrelated things, split into multiple theses.

#### 4) Build + snapshot the **after** binary

```bash
cd /Users/omerba/Workspace/mft
cargo build --release --bin mft_dump
cp -f target/release/mft_dump target/release/mft_dump.h{N}_after
```

#### 5) Benchmark **before vs after in the same hyperfine command**

We always run both saved binaries in a single `hyperfine` invocation and export JSON.

```bash
cd /Users/omerba/Workspace/mft
hyperfine --warmup 5 --runs 40 \
  --export-json target/h{N}-before-vs-after.hyperfine.json \
  './target/release/mft_dump.h{N}_before samples/MFT -o jsonl -f /dev/null --no-confirm-overwrite' \
  './target/release/mft_dump.h{N}_after  samples/MFT -o jsonl -f /dev/null --no-confirm-overwrite'
```

Extract medians quickly (no jq required):

```bash
python3 - <<'PY'
import json
path = "target/h{N}-before-vs-after.hyperfine.json"
d = json.load(open(path))
for r in d["results"]:
    print(r["command"])
    print("  median:", r["times"]["median"])
    print("  mean  :", r["times"]["mean"], "stddev:", r["times"]["stddev"])
PY
```

If variance is high, amortize noise by running multiple iterations inside each hyperfine run:

```bash
cd /Users/omerba/Workspace/mft
hyperfine --warmup 2 --runs 15 \
  --export-json target/h{N}-before-vs-after.hyperfine.json \
  --command-name 'before (20x)' "bash -lc 'for i in {1..20}; do ./target/release/mft_dump.h{N}_before samples/MFT -o jsonl -f /dev/null --no-confirm-overwrite; done'" \
  --command-name 'after  (20x)' "bash -lc 'for i in {1..20}; do ./target/release/mft_dump.h{N}_after  samples/MFT -o jsonl -f /dev/null --no-confirm-overwrite; done'"
```

#### 6) Record an **after** profile (Samply)

```bash
cd /Users/omerba/Workspace/mft
samply record --save-only --unstable-presymbolicate --reuse-threads --main-thread-only \
  -o target/samply/h{N}_after.profile.json.gz \
  --iteration-count 200 -- \
  ./target/release/mft_dump.h{N}_after samples/MFT -o jsonl -f /dev/null --no-confirm-overwrite
```

View:

```bash
cd /Users/omerba/Workspace/mft
samply load --no-open -P 4034 target/samply/h{N}_after.profile.json.gz
```

#### 7) Correctness checks (pick the strictness that matches the thesis)

**Semantic JSONL equality** (preferred; formatting differences allowed):

```bash
cd /Users/omerba/Workspace/mft
rm -f /tmp/mft_before.jsonl /tmp/mft_after.jsonl
./target/release/mft_dump.h{N}_before samples/MFT --ranges 0-200 -o jsonl -f /tmp/mft_before.jsonl --no-confirm-overwrite
./target/release/mft_dump.h{N}_after  samples/MFT --ranges 0-200 -o jsonl -f /tmp/mft_after.jsonl  --no-confirm-overwrite
python3 - <<'PY'
import json
b = [json.loads(l) for l in open("/tmp/mft_before.jsonl")]
a = [json.loads(l) for l in open("/tmp/mft_after.jsonl")]
assert b == a, "semantic JSONL mismatch"
print("OK: semantic JSONL identical (ranges 0-200)")
PY
```

**Byte-for-byte equality** (use when the thesis claims exact output identity):

```bash
diff -u /tmp/mft_before.jsonl /tmp/mft_after.jsonl >/dev/null && echo "OK: byte-identical"
```

#### 8) Update this file (PERF.md) with a write-up

Add a section under “Completed optimizations” (or “Rejected”) with:
- **What changed**
- **Benchmarks** (paste the exact hyperfine command)
- **Extracted medians** (from exported JSON)
- **Speedup** (ratio and %)
- **Profile delta** (top leaf frame(s) before/after, mention if top leaf changed)
- **Correctness check** (command + result)
- **Artifacts**: profile paths + hyperfine JSON path

#### 9) PR-quality finish

Run the usual checks before committing:

```bash
cd /Users/omerba/Workspace/mft
cargo test --all-features
cargo fmt
cargo clippy --all-targets --all-features
```

Then commit with a message that matches the thesis and the observable change (example):

```bash
git commit -am "perf: H{N} avoid resident attribute copies in JSONL"
```

### How to handle negative results (rejected theses)

If the benchmark is within noise or regresses:
- **Revert** the change (keep the branch clean), or leave it but clearly mark as rejected.
- Add a “Rejected” subsection documenting:
  - the hypothesis
  - the benchmark numbers (showing it’s noise/regression)
  - the profile evidence (what got worse / what new leaf appeared)
  - the conclusion (“not worth it”) and what to try next

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

### H4 — Reduce hex formatting overhead (`to_hex_string`)

- **Claim**: hex encoding of raw attribute blobs is still a meaningful formatting cost.
- **Evidence**: leaf frames show `core::fmt::num::<impl UpperHex for u8>::fmt` at ~2% self, and `mft::utils::to_hex_string` in the top leaf list.
- **Change**: replace `to_hex_string`’s `write!(\"{byte:02X}\")` loop with a table-based encoder (no `fmt`).
- **Success metric**: W1 improves by **≥ 2%** on median time (post-H1/H2/H3).
- **Guardrails**: output must be byte-for-byte identical for hex strings (uppercase, no separators).

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

### H3 (2025-12-23) — Migrate timestamps to `jiff` (preserve chrono-compatible output)

**What changed**
- Replace `chrono::DateTime<Utc>` fields in:
  - `StandardInfoAttr` (`0x10`)
  - `FileNameAttr` (`0x30`)
  - `FlatMftEntryWithName` (CSV)
  with `jiff::Timestamp` (re-exported as `mft::Timestamp`).
- Convert Windows FILETIME directly in `mft::utils::windows_filetime_to_timestamp` (truncate to microseconds to match historical behavior).
- Preserve the exact JSON/CSV timestamp string format by forcing chrono-compatible RFC3339 precision using `jiff::fmt::temporal::DateTimePrinter` (via `#[serde(serialize_with = ...)]`).
- Enable `jiff`’s `perf-inline` feature (important when using `default-features = false`; it’s enabled by default otherwise).

**Benchmarks**

Single `hyperfine` run comparing saved binaries:

```bash
hyperfine --warmup 5 --runs 40 \
  './target/release/mft_dump.h3_before samples/MFT -o jsonl -f /dev/null --no-confirm-overwrite' \
  './target/release/mft_dump.h3_after_final samples/MFT -o jsonl -f /dev/null --no-confirm-overwrite'
```

Extracted medians (from `target/h3-before-vs-after-final.hyperfine.json`):
- **Before median**: **69.21 ms**
- **After median**: **64.65 ms**
- **Speedup**: ~**1.07×** (≈ **6.6%** faster)

**Profile delta (leaf shift)**

Before (`target/samply/h3_before.profile.json.gz`, inverted call tree) included:
- `chrono::...FormatIso8601...::fmt` (~0.8% self)
- `chrono::naive::date::NaiveDate::add_days` (~1.2% self)

After (`target/samply/h3_after_final.profile.json.gz`, inverted call tree):
- No `chrono::` frames in the top leaf list
- Timestamp formatting is now primarily `jiff::fmt::temporal::printer::DateTimePrinter::print_datetime` (~3.9% self)

Profiles:
- `target/samply/h3_before.profile.json.gz`
- `target/samply/h3_after_final.profile.json.gz`

**Correctness check**

We verified **semantic equality** of JSONL output (including timestamp strings) on a small range:
- Command: both binaries with `--ranges 0-200` and `-o jsonl`
- Method: parse each line as JSON and compare Python objects
- Result: OK (193 lines)

### H4 (2025-12-23) — Faster hex encoding (remove `fmt`-based per-byte formatting)

**What changed**
- Replaced `mft::utils::to_hex_string`’s per-byte `write!(\"{byte:02X}\")` loop with a nibble lookup table and `String::push` (no `core::fmt::UpperHex` formatting path).
- Added a small unit test to lock in uppercase, separator-free output.

**Benchmarks**

Single `hyperfine` run comparing the saved binaries:

```bash
hyperfine --warmup 5 --runs 40 \
  './target/release/mft_dump.h4_before samples/MFT -o jsonl -f /dev/null --no-confirm-overwrite' \
  './target/release/mft_dump.h4_after2 samples/MFT -o jsonl -f /dev/null --no-confirm-overwrite'
```

Extracted medians (from `target/h4-before-vs-after2.hyperfine.json`):
- **Before median**: **63.31 ms**
- **After median**: **57.81 ms**
- **Speedup**: ~**1.10×** (≈ **8.7%** faster)

**Profile delta (leaf reduction)**

Before (`target/samply/h4_before.profile.json.gz`, inverted call tree):
- `core::fmt::num::<impl UpperHex for u8>::fmt` ~2.3% self

After (`target/samply/h4_after2.profile.json.gz`, inverted call tree):
- `UpperHex` no longer appears in the top leaf list
- `mft::utils::to_hex_string` is still visible (~1.3% self), but the heavy `fmt` machinery is gone

Profiles:
- `target/samply/h4_before.profile.json.gz`
- `target/samply/h4_after2.profile.json.gz`


