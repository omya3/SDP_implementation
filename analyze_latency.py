#!/usr/bin/env python3
import argparse
import csv
import json
import math
from pathlib import Path
from statistics import mean, pstdev, median
from typing import List, Tuple

try:
    import matplotlib.pyplot as plt  # optional; only used with --plots
except Exception:
    plt = None


def read_latencies(path: Path) -> Tuple[List[float], int, int]:
    """
    Reads spa_latency.csv with columns: request#, latency_ms, success
    Returns (latencies_ms_success_only, total_rows, failed_rows)
    """
    latencies = []
    total = 0
    failed = 0
    with path.open(newline="") as f:
        r = csv.DictReader(f)
        for row in r:
            total += 1
            success = (row.get("success", "").strip().lower() == "yes")
            val = row.get("latency_ms", "").strip()
            if success:
                try:
                    lat = float(val)
                    if math.isfinite(lat):
                        latencies.append(lat)
                    else:
                        failed += 1
                except Exception:
                    failed += 1
            else:
                failed += 1
    return latencies, total, failed


def percentile(data: List[float], p: float) -> float:
    """Linear interpolation percentile (p in [0,100])"""
    if not data:
        return float("nan")
    if p <= 0:
        return data[0]
    if p >= 100:
        return data[-1]
    k = (len(data)-1) * (p/100.0)
    f = math.floor(k)
    c = math.ceil(k)
    if f == c:
        return data[int(k)]
    d0 = data[f] * (c - k)
    d1 = data[c] * (k - f)
    return d0 + d1


def summarize(latencies: List[float], total: int, failed: int, duration_s: float = None):
    latencies_sorted = sorted(latencies)
    succ = len(latencies_sorted)
    success_rate = (succ / total * 100.0) if total else 0.0

    # core stats
    mn = latencies_sorted[0] if succ else float("nan")
    mx = latencies_sorted[-1] if succ else float("nan")
    avg = mean(latencies_sorted) if succ else float("nan")
    med = median(latencies_sorted) if succ else float("nan")
    sd = pstdev(latencies_sorted) if succ else float("nan")
    cov = (sd / avg) if succ and avg else float("nan")

    # percentiles
    p50 = percentile(latencies_sorted, 50)
    p90 = percentile(latencies_sorted, 90)
    p95 = percentile(latencies_sorted, 95)
    p99 = percentile(latencies_sorted, 99)

    # jitter (change between consecutive requests)
    jitter = float("nan")
    if succ > 1:
        diffs = [latencies[i+1] - latencies[i] for i in range(len(latencies)-1)]
        jitter = pstdev(diffs)

    # outliers by IQR
    q1 = percentile(latencies_sorted, 25)
    q3 = percentile(latencies_sorted, 75)
    iqr = q3 - q1
    fence_hi = q3 + 1.5 * iqr
    outliers = sum(1 for x in latencies_sorted if x > fence_hi)

    # throughput if duration provided
    rps = (total / duration_s) if duration_s and duration_s > 0 else None
    sps = (succ / duration_s) if duration_s and duration_s > 0 else None

    return {
        "total_requests": total,
        "successful": succ,
        "failed": failed,
        "success_rate_pct": round(success_rate, 3),
        "latency_ms": {
            "min": round(mn, 3) if succ else None,
            "p50": round(p50, 3) if succ else None,
            "p90": round(p90, 3) if succ else None,
            "p95": round(p95, 3) if succ else None,
            "p99": round(p99, 3) if succ else None,
            "max": round(mx, 3) if succ else None,
            "avg": round(avg, 3) if succ else None,
            "median": round(med, 3) if succ else None,
            "stddev": round(sd, 3) if succ else None,
            "cv": round(cov, 6) if succ and cov == cov else None,  # coefficient of variation
            "jitter_stddev": round(jitter, 6) if jitter == jitter else None,
            "iqr_q1": round(q1, 3) if succ else None,
            "iqr_q3": round(q3, 3) if succ else None,
            "iqr": round(iqr, 3) if succ else None,
            "outliers_gt_q3_plus_1p5iqr": int(outliers) if succ else None
        },
        "duration_seconds": duration_s,
        "throughput_rps_total": round(rps, 3) if rps is not None else None,
        "throughput_rps_success": round(sps, 3) if sps is not None else None,
    }


def write_summary_json(summary, out_path: Path):
    out_path.write_text(json.dumps(summary, indent=2))
    print(f"[OK] Wrote summary JSON -> {out_path}")


def write_clean_series(latencies: List[float], out_path: Path):
    with out_path.open("w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["index", "latency_ms"])
        for i, v in enumerate(latencies, 1):
            w.writerow([i, f"{v:.6f}"])
    print(f"[OK] Wrote cleaned series -> {out_path}")


def make_plots(latencies: List[float], out_dir: Path, title_prefix: str):
    if plt is None:
        print("[WARN] matplotlib not available; skipping plots.")
        return
    out_dir.mkdir(parents=True, exist_ok=True)
    # 1) Index vs latency
    plt.figure()
    plt.plot(range(1, len(latencies)+1), latencies)
    plt.xlabel("Request index")
    plt.ylabel("Latency (ms)")
    plt.title(f"{title_prefix} – Latency vs Request Index")
    plt.tight_layout()
    plt.savefig(out_dir / "series.png"); plt.close()

    # 2) Histogram
    plt.figure()
    plt.hist(latencies, bins=50)
    plt.xlabel("Latency (ms)")
    plt.ylabel("Count")
    plt.title(f"{title_prefix} – Latency Histogram")
    plt.tight_layout()
    plt.savefig(out_dir / "hist.png"); plt.close()

    # 3) ECDF
    xs = sorted(latencies)
    ys = [i/len(xs) for i in range(1, len(xs)+1)]
    plt.figure()
    plt.plot(xs, ys)
    plt.xlabel("Latency (ms)")
    plt.ylabel("ECDF")
    plt.title(f"{title_prefix} – Latency ECDF")
    plt.tight_layout()
    plt.savefig(out_dir / "ecdf.png"); plt.close()

    print(f"[OK] Plots saved under -> {out_dir}/")


def main():
    ap = argparse.ArgumentParser(description="Analyze SPA latency CSV.")
    ap.add_argument("csv_path", help="Path to spa_latency.csv")
    ap.add_argument("--duration", type=float, default=None,
                    help="Total test duration in seconds (optional, for RPS)")
    ap.add_argument("--outdir", default="latency_report",
                    help="Directory to write summary/series/plots")
    ap.add_argument("--plots", action="store_true",
                    help="Generate PNG plots (requires matplotlib)")
    args = ap.parse_args()

    csv_path = Path(args.csv_path)
    out_dir = Path(args.outdir)
    out_dir.mkdir(parents=True, exist_ok=True)

    latencies, total, failed = read_latencies(csv_path)
    summary = summarize(latencies, total, failed, duration_s=args.duration)

    # Print summary
    print("\n=== LATENCY SUMMARY ===")
    print(json.dumps(summary, indent=2))

    # Write artifacts
    write_summary_json(summary, out_dir / "summary.json")
    write_clean_series(latencies, out_dir / "latency_series.csv")
    if args.plots and latencies:
        make_plots(latencies, out_dir / "plots", title_prefix=csv_path.name)


if __name__ == "__main__":
    main()
