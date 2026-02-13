#!/usr/bin/env python3
"""Analyze palisade benchmark results and generate charts.

Input format expected (from palisade_benchmark_results.txt):
<Label> │ Time: <value> <unit> │ Alloc: <bytes> B (<calls> calls) │ Dealloc: ... │ Net: ...

The script writes:
- parsed_rows.csv: all parsed benchmark records
- summary.csv: per-label aggregates
- summary.json: same summary in JSON
- charts/*.png: visualizations
"""

from __future__ import annotations

import argparse
import csv
import json
import math
import os
import re
import statistics
from collections import defaultdict
from dataclasses import dataclass, asdict
from typing import Dict, List, Tuple

try:
    import matplotlib.pyplot as plt
except ImportError as exc:  # pragma: no cover
    raise SystemExit(
        "matplotlib is required for chart generation. Install with: pip install matplotlib"
    ) from exc


HEADER_RE = re.compile(r"Unix timestamp:\s*(\d+)")
ROW_RE = re.compile(
    r"^\s*(?P<label>.*?)\s*│\s*Time:\s*(?P<time>[-+]?\d+(?:\.\d+)?)\s*(?P<unit>ns|µs|us|ms|s)\s*"
    r"│\s*Alloc:\s*(?P<alloc>-?\d+)\s*B\s*\(\s*(?P<alloc_calls>\d+)\s*calls\)\s*"
    r"│\s*Dealloc:\s*(?P<dealloc>-?\d+)\s*B\s*\(\s*(?P<dealloc_calls>\d+)\s*calls\)\s*"
    r"│\s*Net:\s*(?P<net>-?\d+)\s*B\s*$"
)


@dataclass
class BenchRow:
    session_ts: int
    label: str
    time_ns: float
    alloc_bytes: int
    alloc_calls: int
    dealloc_bytes: int
    dealloc_calls: int
    net_bytes: int


@dataclass
class LabelSummary:
    label: str
    n: int
    time_ns_mean: float
    time_ns_median: float
    time_ns_p95: float
    time_ns_min: float
    time_ns_max: float
    alloc_bytes_median: float
    alloc_calls_median: float
    dealloc_bytes_median: float
    net_bytes_median: float


def to_ns(value: float, unit: str) -> float:
    if unit == "ns":
        return value
    if unit in ("µs", "us"):
        return value * 1_000.0
    if unit == "ms":
        return value * 1_000_000.0
    if unit == "s":
        return value * 1_000_000_000.0
    raise ValueError(f"Unsupported unit: {unit}")


def percentile(sorted_vals: List[float], p: float) -> float:
    if not sorted_vals:
        return float("nan")
    if p <= 0:
        return sorted_vals[0]
    if p >= 100:
        return sorted_vals[-1]
    k = (len(sorted_vals) - 1) * (p / 100.0)
    lo = math.floor(k)
    hi = math.ceil(k)
    if lo == hi:
        return sorted_vals[int(k)]
    return sorted_vals[lo] + (sorted_vals[hi] - sorted_vals[lo]) * (k - lo)


def parse_file(path: str) -> List[BenchRow]:
    rows: List[BenchRow] = []
    current_ts = 0

    with open(path, "r", encoding="utf-8", errors="replace") as f:
        for line_no, line in enumerate(f, start=1):
            line = line.rstrip("\n")
            header_match = HEADER_RE.search(line)
            if header_match:
                current_ts = int(header_match.group(1))
                continue

            match = ROW_RE.match(line)
            if not match:
                continue

            gd = match.groupdict()
            rows.append(
                BenchRow(
                    session_ts=current_ts,
                    label=gd["label"].strip(),
                    time_ns=to_ns(float(gd["time"]), gd["unit"]),
                    alloc_bytes=int(gd["alloc"]),
                    alloc_calls=int(gd["alloc_calls"]),
                    dealloc_bytes=int(gd["dealloc"]),
                    dealloc_calls=int(gd["dealloc_calls"]),
                    net_bytes=int(gd["net"]),
                )
            )

    return rows


def summarize(rows: List[BenchRow]) -> List[LabelSummary]:
    by_label: Dict[str, List[BenchRow]] = defaultdict(list)
    for r in rows:
        by_label[r.label].append(r)

    output: List[LabelSummary] = []
    for label, items in by_label.items():
        times = sorted(r.time_ns for r in items)
        alloc_bytes = sorted(r.alloc_bytes for r in items)
        alloc_calls = sorted(r.alloc_calls for r in items)
        dealloc_bytes = sorted(r.dealloc_bytes for r in items)
        net_bytes = sorted(r.net_bytes for r in items)

        output.append(
            LabelSummary(
                label=label,
                n=len(items),
                time_ns_mean=statistics.fmean(times),
                time_ns_median=statistics.median(times),
                time_ns_p95=percentile(times, 95),
                time_ns_min=min(times),
                time_ns_max=max(times),
                alloc_bytes_median=statistics.median(alloc_bytes),
                alloc_calls_median=statistics.median(alloc_calls),
                dealloc_bytes_median=statistics.median(dealloc_bytes),
                net_bytes_median=statistics.median(net_bytes),
            )
        )

    output.sort(key=lambda s: s.time_ns_median)
    return output


def write_parsed_rows(rows: List[BenchRow], out_csv: str) -> None:
    with open(out_csv, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(
            f,
            fieldnames=[
                "session_ts",
                "label",
                "time_ns",
                "alloc_bytes",
                "alloc_calls",
                "dealloc_bytes",
                "dealloc_calls",
                "net_bytes",
            ],
        )
        w.writeheader()
        for r in rows:
            w.writerow(asdict(r))


def write_summary(summary: List[LabelSummary], out_csv: str, out_json: str) -> None:
    dict_rows = [asdict(s) for s in summary]

    with open(out_csv, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=list(dict_rows[0].keys()) if dict_rows else ["label"])
        w.writeheader()
        w.writerows(dict_rows)

    with open(out_json, "w", encoding="utf-8") as f:
        json.dump(dict_rows, f, indent=2)


def chart_time_distribution(rows: List[BenchRow], out_png: str, top_n: int) -> None:
    by_label: Dict[str, List[float]] = defaultdict(list)
    for r in rows:
        by_label[r.label].append(r.time_ns / 1_000.0)  # us

    ranked = sorted(by_label.items(), key=lambda kv: statistics.median(kv[1]), reverse=True)
    selected = ranked[:top_n]

    labels = [k for k, _ in selected]
    series = [v for _, v in selected]

    plt.figure(figsize=(14, 7))
    plt.boxplot(series, tick_labels=labels, showfliers=False)
    plt.xticks(rotation=30, ha="right")
    plt.ylabel("Time (µs)")
    plt.title(f"Time Distribution by Benchmark (Top {top_n} by median)")
    plt.tight_layout()
    plt.savefig(out_png, dpi=150)
    plt.close()


def chart_alloc_bar(summary: List[LabelSummary], out_png: str, top_n: int) -> None:
    ranked = sorted(summary, key=lambda s: s.alloc_bytes_median, reverse=True)[:top_n]
    labels = [s.label for s in ranked]
    vals = [s.alloc_bytes_median for s in ranked]

    plt.figure(figsize=(14, 7))
    plt.bar(labels, vals)
    plt.xticks(rotation=30, ha="right")
    plt.ylabel("Median allocated bytes")
    plt.title(f"Top {top_n} Benchmarks by Median Allocation")
    plt.tight_layout()
    plt.savefig(out_png, dpi=150)
    plt.close()


def chart_time_vs_alloc(summary: List[LabelSummary], out_png: str) -> None:
    xs = [s.alloc_bytes_median for s in summary]
    ys = [s.time_ns_median / 1_000.0 for s in summary]  # us

    plt.figure(figsize=(10, 7))
    plt.scatter(xs, ys, alpha=0.8)
    for s in summary:
        if s.alloc_bytes_median == 0 or s.time_ns_median == min(x.time_ns_median for x in summary):
            plt.annotate(s.label, (s.alloc_bytes_median, s.time_ns_median / 1_000.0), fontsize=8)
    plt.xlabel("Median allocated bytes")
    plt.ylabel("Median time (µs)")
    plt.title("Median Time vs Median Allocation")
    plt.tight_layout()
    plt.savefig(out_png, dpi=150)
    plt.close()


def chart_zero_alloc_ratio(summary: List[LabelSummary], out_png: str) -> None:
    labels = [s.label for s in summary]
    is_zero = [1 if s.alloc_bytes_median == 0 else 0 for s in summary]

    plt.figure(figsize=(14, 4))
    plt.bar(labels, is_zero)
    plt.xticks(rotation=30, ha="right")
    plt.yticks([0, 1], ["alloc", "zero-alloc"])
    plt.title("Zero-Allocation Status (by median alloc bytes)")
    plt.tight_layout()
    plt.savefig(out_png, dpi=150)
    plt.close()


def ensure_dir(path: str) -> None:
    os.makedirs(path, exist_ok=True)


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Analyze palisade benchmark results and generate charts",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python3 scripts/analyze_bench_results.py\n"
            "  python3 scripts/analyze_bench_results.py --input palisade_benchmark_results.txt --outdir benchmark_analysis\n"
            "  python3 scripts/analyze_bench_results.py --top-n 20\n"
        ),
    )
    p.add_argument("--input", default="palisade_benchmark_results.txt", help="Path to benchmark results file")
    p.add_argument("--outdir", default="benchmark_analysis", help="Output directory")
    p.add_argument("--top-n", type=int, default=12, help="Top N labels to include in ranked charts")
    return p.parse_args()


def main() -> None:
    args = parse_args()
    ensure_dir(args.outdir)
    charts_dir = os.path.join(args.outdir, "charts")
    ensure_dir(charts_dir)

    rows = parse_file(args.input)
    if not rows:
        raise SystemExit(f"No benchmark rows found in {args.input}")

    summary = summarize(rows)

    write_parsed_rows(rows, os.path.join(args.outdir, "parsed_rows.csv"))
    write_summary(
        summary,
        os.path.join(args.outdir, "summary.csv"),
        os.path.join(args.outdir, "summary.json"),
    )

    chart_time_distribution(rows, os.path.join(charts_dir, "time_distribution.png"), args.top_n)
    chart_alloc_bar(summary, os.path.join(charts_dir, "alloc_median_top.png"), args.top_n)
    chart_time_vs_alloc(summary, os.path.join(charts_dir, "time_vs_alloc.png"))
    chart_zero_alloc_ratio(summary, os.path.join(charts_dir, "zero_alloc_status.png"))

    print(f"Parsed rows: {len(rows)}")
    print(f"Unique benchmarks: {len(summary)}")
    print(f"Wrote analysis to: {args.outdir}")


if __name__ == "__main__":
    main()
