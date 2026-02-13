# Benchmark Analysis Script Usage

Script: `scripts/analyze_bench_results.py`

## Prerequisites

1. Python 3.9+.
2. `matplotlib` installed:

```bash
python3 -m pip install matplotlib
```

## Basic Usage

Run with defaults:

```bash
python3 scripts/analyze_bench_results.py
```

Defaults used:
- Input: `palisade_benchmark_results.txt`
- Output directory: `benchmark_analysis`
- Top N for ranked charts: `12`

## Common Examples

Analyze a specific file and output directory:

```bash
python3 scripts/analyze_bench_results.py \
  --input palisade_benchmark_results.txt \
  --outdir benchmark_analysis
```

Generate charts with larger top-N ranking:

```bash
python3 scripts/analyze_bench_results.py --top-n 20
```

Keep analyses per run:

```bash
python3 scripts/analyze_bench_results.py --outdir benchmark_analysis_$(date +%Y%m%d_%H%M%S)
```

## Outputs

After running, you get:

- `benchmark_analysis/parsed_rows.csv`: row-level parsed benchmark data
- `benchmark_analysis/summary.csv`: per-label aggregate metrics
- `benchmark_analysis/summary.json`: same summary in JSON
- `benchmark_analysis/charts/time_distribution.png`
- `benchmark_analysis/charts/alloc_median_top.png`
- `benchmark_analysis/charts/time_vs_alloc.png`
- `benchmark_analysis/charts/zero_alloc_status.png`

## Example Quick Checks

Top 10 benchmarks by median allocation bytes:

```bash
python3 - <<'PY'
import csv
rows = []
with open("benchmark_analysis/summary.csv", newline="", encoding="utf-8") as f:
    for r in csv.DictReader(f):
        rows.append((r["label"], float(r["alloc_bytes_median"])))
rows.sort(key=lambda x: x[1], reverse=True)
for label, alloc in rows[:10]:
    print(f"{alloc:10.0f}  {label}")
PY
```

Top 10 slowest by median time:

```bash
python3 - <<'PY'
import csv
rows = []
with open("benchmark_analysis/summary.csv", newline="", encoding="utf-8") as f:
    for r in csv.DictReader(f):
        rows.append((r["label"], float(r["time_ns_median"]) / 1000.0))
rows.sort(key=lambda x: x[1], reverse=True)
for label, time_us in rows[:10]:
    print(f"{time_us:10.2f} us  {label}")
PY
```
