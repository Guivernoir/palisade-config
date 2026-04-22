# Benchmark Analysis Script Usage

## Purpose

`scripts/analyze_bench_results.py` converts raw benchmark output into a compact
set of structured artifacts suitable for comparative review:

- parsed row data
- aggregate summaries
- ranking views
- visual distributions

The script is intended to support performance interpretation, not to replace a
formal benchmarking methodology.

## Prerequisites

- Python 3.9 or newer
- `matplotlib`

Install the plotting dependency with:

```bash
python3 -m pip install matplotlib
```

## Canonical Invocation

Run with default settings:

```bash
python3 scripts/analyze_bench_results.py
```

Default parameters:

- input file: `palisade_benchmark_results.txt`
- output directory: `benchmark_analysis`
- ranked chart depth: `12`

## Common Variants

Analyze a specific input file and destination directory:

```bash
python3 scripts/analyze_bench_results.py \
  --input palisade_benchmark_results.txt \
  --outdir benchmark_analysis
```

Increase the top-N depth in ranked charts:

```bash
python3 scripts/analyze_bench_results.py --top-n 20
```

Preserve each run independently:

```bash
python3 scripts/analyze_bench_results.py \
  --outdir benchmark_analysis_$(date +%Y%m%d_%H%M%S)
```

## Output Set

The script produces:

- `benchmark_analysis/parsed_rows.csv`
- `benchmark_analysis/summary.csv`
- `benchmark_analysis/summary.json`
- `benchmark_analysis/charts/time_distribution.png`
- `benchmark_analysis/charts/alloc_median_top.png`
- `benchmark_analysis/charts/time_vs_alloc.png`
- `benchmark_analysis/charts/zero_alloc_status.png`

## Interpretation Guidance

The most useful reading sequence is:

1. `summary.csv` for ranked numerical review
2. `time_distribution.png` for timing spread
3. `alloc_median_top.png` for allocation outliers
4. `zero_alloc_status.png` for hot-path allocation posture

Questions the artifacts help answer:

- which operations dominate median latency
- which operations allocate unexpectedly
- whether "zero-allocation" claims hold in measured practice
- where optimization effort is likely to have the best operational return

## Quick Checks

Top 10 benchmarks by median allocation bytes:

```bash
python3 - <<'PY'
import csv
rows = []
with open("benchmark_analysis/summary.csv", newline="", encoding="utf-8") as f:
    for row in csv.DictReader(f):
        rows.append((row["label"], float(row["alloc_bytes_median"])))
rows.sort(key=lambda item: item[1], reverse=True)
for label, alloc in rows[:10]:
    print(f"{alloc:10.0f}  {label}")
PY
```

Top 10 slowest benchmarks by median time:

```bash
python3 - <<'PY'
import csv
rows = []
with open("benchmark_analysis/summary.csv", newline="", encoding="utf-8") as f:
    for row in csv.DictReader(f):
        rows.append((row["label"], float(row["time_ns_median"]) / 1000.0))
rows.sort(key=lambda item: item[1], reverse=True)
for label, time_us in rows[:10]:
    print(f"{time_us:10.2f} us  {label}")
PY
```

## Limitations

This script assumes:

- the benchmark text format matches the parser's expectations
- the benchmark runs themselves were obtained under a controlled methodology
- charts are used as review aids rather than as standalone proof

For credible performance claims, keep raw benchmark inputs, environment notes,
compiler flags, and commit identifiers alongside the generated analysis.
