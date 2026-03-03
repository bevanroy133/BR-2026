"""Performance benchmark harness for analyzer regression tracking.

Usage:
    python -m harness.benchmark_harness
    python -m harness.benchmark_harness --write-baseline
"""

from __future__ import annotations

import argparse
import json
import platform
import statistics
import sys
import tempfile
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

from harness.scenarios import email_scenarios, materialize_file_scenarios, url_scenarios
from modules.analyzer import analyze_file, analyze_url
from modules.email_analyzer import analyze_email_message


@dataclass(frozen=True)
class BenchCase:
    case_id: str
    group: str
    run: Callable[[], dict]


def _percentile_ms(samples_ms: list[float], percentile: float) -> float:
    if not samples_ms:
        return 0.0
    ordered = sorted(samples_ms)
    index = int(round((len(ordered) - 1) * percentile))
    return ordered[max(0, min(index, len(ordered) - 1))]


def _measure_case(case: BenchCase, *, warmup: int, iterations: int) -> dict:
    # Warmup reduces one-time effects (imports/caches, first allocs).
    for _ in range(warmup):
        case.run()

    samples_ms: list[float] = []
    for _ in range(iterations):
        start = time.perf_counter()
        case.run()
        elapsed_ms = (time.perf_counter() - start) * 1000.0
        samples_ms.append(elapsed_ms)

    return {
        "case_id": case.case_id,
        "group": case.group,
        "iterations": iterations,
        "mean_ms": round(statistics.fmean(samples_ms), 3),
        "median_ms": round(statistics.median(samples_ms), 3),
        "p95_ms": round(_percentile_ms(samples_ms, 0.95), 3),
        "min_ms": round(min(samples_ms), 3),
        "max_ms": round(max(samples_ms), 3),
    }


def _build_cases(workdir: Path) -> list[BenchCase]:
    cases: list[BenchCase] = []
    # File cases are materialized once and wrapped by closures.
    file_paths = materialize_file_scenarios(workdir)
    for scenario, path in file_paths:
        cases.append(
            BenchCase(
                case_id=scenario.case_id,
                group="file",
                run=lambda p=str(path): analyze_file(p, vt_api_key=""),
            )
        )

    # URL and email cases do not need temp files.
    for scenario in url_scenarios():
        cases.append(
            BenchCase(
                case_id=scenario.case_id,
                group="url",
                run=lambda u=scenario.raw_url: analyze_url(u, gsb_api_key=""),
            )
        )
    for scenario in email_scenarios():
        cases.append(
            BenchCase(
                case_id=scenario.case_id,
                group="email",
                run=lambda raw=scenario.raw_email: analyze_email_message(raw),
            )
        )
    return cases


def _summarize_groups(rows: list[dict]) -> dict:
    grouped: dict[str, list[float]] = {}
    for row in rows:
        grouped.setdefault(row["group"], []).append(float(row["mean_ms"]))
    return {
        group: {
            "case_count": len(values),
            "mean_of_means_ms": round(statistics.fmean(values), 3),
            "max_mean_ms": round(max(values), 3),
        }
        for group, values in grouped.items()
    }


def _compare_to_baseline(
    rows: list[dict],
    baseline_path: Path,
    *,
    max_regression_pct: float,
) -> dict:
    if not baseline_path.exists():
        return {
            "baseline_found": False,
            "max_regression_pct": max_regression_pct,
            "regressions": [],
            "deltas": [],
        }

    baseline = json.loads(baseline_path.read_text(encoding="utf-8"))
    baseline_rows = baseline.get("cases", [])
    baseline_map = {row["case_id"]: float(row["mean_ms"]) for row in baseline_rows}

    deltas: list[dict] = []
    regressions: list[dict] = []
    for row in rows:
        case_id = row["case_id"]
        if case_id not in baseline_map:
            continue
        base = baseline_map[case_id]
        curr = float(row["mean_ms"])
        if base <= 0:
            continue
        delta_pct = ((curr - base) / base) * 100.0
        delta_row = {
            "case_id": case_id,
            "baseline_mean_ms": round(base, 3),
            "current_mean_ms": round(curr, 3),
            "delta_pct": round(delta_pct, 2),
        }
        deltas.append(delta_row)
        if delta_pct > max_regression_pct:
            regressions.append(delta_row)

    return {
        "baseline_found": True,
        "max_regression_pct": max_regression_pct,
        "regressions": regressions,
        "deltas": deltas,
    }


def run_benchmarks(
    *,
    iterations: int,
    warmup: int,
    output_path: Path,
    baseline_path: Path,
    max_regression_pct: float,
    write_baseline: bool,
) -> int:
    with tempfile.TemporaryDirectory(prefix="sda-benchmark-") as tmp:
        cases = _build_cases(Path(tmp))
        # Measure while temporary fixture files still exist.
        rows = [_measure_case(case, warmup=warmup, iterations=iterations) for case in cases]
    payload = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "python": sys.version,
        "platform": platform.platform(),
        "iterations": iterations,
        "warmup": warmup,
        "cases": rows,
        "group_summary": _summarize_groups(rows),
    }

    baseline_cmp = _compare_to_baseline(
        rows,
        baseline_path,
        max_regression_pct=max_regression_pct,
    )
    payload["baseline_comparison"] = baseline_cmp

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    print(f"Benchmark report written: {output_path}")

    if write_baseline:
        baseline_path.parent.mkdir(parents=True, exist_ok=True)
        baseline_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        print(f"Baseline updated: {baseline_path}")
        return 0

    for row in rows:
        print(
            f"[{row['group']}] {row['case_id']}: "
            f"mean={row['mean_ms']}ms p95={row['p95_ms']}ms"
        )

    if not baseline_cmp["baseline_found"]:
        print("No baseline found; skipping regression gate.")
        return 0

    regressions = baseline_cmp["regressions"]
    if regressions:
        print(
            f"Performance regression gate failed: "
            f"{len(regressions)} case(s) exceeded {max_regression_pct}% slowdown."
        )
        for row in regressions:
            print(
                f" - {row['case_id']}: baseline={row['baseline_mean_ms']}ms, "
                f"current={row['current_mean_ms']}ms, delta={row['delta_pct']}%"
            )
        return 1

    print("Performance regression gate passed.")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Run local analyzer benchmarks.")
    parser.add_argument("--iterations", type=int, default=40)
    parser.add_argument("--warmup", type=int, default=5)
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("harness") / "benchmark_report.json",
    )
    parser.add_argument(
        "--baseline",
        type=Path,
        default=Path("harness") / "benchmark_baseline.json",
    )
    parser.add_argument("--max-regression-pct", type=float, default=30.0)
    parser.add_argument("--write-baseline", action="store_true")
    args = parser.parse_args()

    return run_benchmarks(
        iterations=args.iterations,
        warmup=args.warmup,
        output_path=args.output,
        baseline_path=args.baseline,
        max_regression_pct=args.max_regression_pct,
        write_baseline=args.write_baseline,
    )


if __name__ == "__main__":
    raise SystemExit(main())
