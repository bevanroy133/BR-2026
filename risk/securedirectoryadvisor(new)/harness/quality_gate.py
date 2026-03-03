"""Unified quality gate runner for local and CI usage.

This command runs all required quality stages in a single entrypoint:
1) Python compile gate
2) Regression harness
3) Benchmark harness
4) Release quality metrics pipeline

Usage:
    python -m harness.quality_gate
"""

from __future__ import annotations

import argparse
import json
import py_compile
from datetime import datetime, timezone
from pathlib import Path

from harness.benchmark_harness import run_benchmarks
from harness.quality_metrics_pipeline import GateThresholds, run_quality_metrics_pipeline
from harness.regression_harness import run_regressions


def _default_release_id() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def _compile_python_sources(repo_root: Path) -> list[str]:
    """Compile all Python modules and return compile error messages."""
    errors: list[str] = []
    # Keep compile scope focused on source trees used by the app and harness.
    include_roots = ("modules", "harness")
    include_files = ("main.py",)

    candidates: list[Path] = []
    for rel_file in include_files:
        path = repo_root / rel_file
        if path.exists():
            candidates.append(path)
    for rel_root in include_roots:
        root = repo_root / rel_root
        if not root.exists():
            continue
        for path in root.rglob("*.py"):
            # Skip bytecode cache and hidden folders.
            if "__pycache__" in path.parts:
                continue
            if any(part.startswith(".") for part in path.parts):
                continue
            candidates.append(path)

    for path in sorted(set(candidates)):
        try:
            py_compile.compile(str(path), doraise=True)
        except Exception as exc:
            errors.append(f"{path}: {exc}")
    return errors


def _ensure_parent(path: Path):
    path.parent.mkdir(parents=True, exist_ok=True)


def run_quality_gate(
    *,
    repo_root: Path,
    release_id: str,
    regression_report_path: Path,
    benchmark_report_path: Path,
    release_metrics_output: Path,
    release_metrics_history: Path,
    release_metrics_summary: Path,
    benchmark_baseline_path: Path,
    benchmark_iterations: int,
    benchmark_warmup: int,
    benchmark_max_regression_pct: float,
    write_benchmark_baseline: bool,
    thresholds: GateThresholds,
) -> int:
    print("== Stage 1/4: Python compile gate ==")
    compile_errors = _compile_python_sources(repo_root)
    if compile_errors:
        print(f"Compile gate failed ({len(compile_errors)} error(s)):")
        for err in compile_errors:
            print(f" - {err}")
        return 1
    print("Compile gate passed.")

    print("\n== Stage 2/4: Regression harness ==")
    regression_payload = run_regressions()
    _ensure_parent(regression_report_path)
    regression_report_path.write_text(
        json.dumps(regression_payload, indent=2),
        encoding="utf-8",
    )
    failed_regressions = int(regression_payload.get("summary", {}).get("failed", 0))
    print(
        f"Regression complete: total={regression_payload['summary']['total']} "
        f"passed={regression_payload['summary']['passed']} "
        f"failed={failed_regressions}"
    )
    if failed_regressions > thresholds.max_failed_regressions:
        print(
            f"Regression gate failed: {failed_regressions} failures exceed "
            f"threshold {thresholds.max_failed_regressions}."
        )
        return 1

    print("\n== Stage 3/4: Benchmark harness ==")
    bench_exit = run_benchmarks(
        iterations=benchmark_iterations,
        warmup=benchmark_warmup,
        output_path=benchmark_report_path,
        baseline_path=benchmark_baseline_path,
        max_regression_pct=benchmark_max_regression_pct,
        write_baseline=write_benchmark_baseline,
    )
    if bench_exit != 0:
        print("Benchmark stage failed.")
        return bench_exit

    print("\n== Stage 4/4: Release metrics pipeline ==")
    metrics_exit = run_quality_metrics_pipeline(
        release_id=release_id,
        regression_report_path=regression_report_path,
        benchmark_report_path=benchmark_report_path,
        output_path=release_metrics_output,
        history_path=release_metrics_history,
        summary_md_path=release_metrics_summary,
        thresholds=thresholds,
        run_inputs=False,
        benchmark_baseline_path=benchmark_baseline_path,
        benchmark_iterations=benchmark_iterations,
        benchmark_warmup=benchmark_warmup,
        benchmark_max_regression_pct=benchmark_max_regression_pct,
    )
    if metrics_exit != 0:
        print("Release metrics gate failed.")
        return metrics_exit

    print("\nQuality gate passed.")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Run full quality gate pipeline.")
    parser.add_argument("--release-id", default=_default_release_id())
    parser.add_argument(
        "--regression-report",
        type=Path,
        default=Path("harness") / "regression_report.json",
    )
    parser.add_argument(
        "--benchmark-report",
        type=Path,
        default=Path("harness") / "benchmark_report.json",
    )
    parser.add_argument(
        "--benchmark-baseline",
        type=Path,
        default=Path("harness") / "benchmark_baseline.json",
    )
    parser.add_argument("--benchmark-iterations", type=int, default=40)
    parser.add_argument("--benchmark-warmup", type=int, default=5)
    parser.add_argument("--benchmark-max-regression-pct", type=float, default=30.0)
    parser.add_argument("--write-benchmark-baseline", action="store_true")
    parser.add_argument(
        "--metrics-output",
        type=Path,
        default=Path("harness") / "release_metrics.json",
    )
    parser.add_argument(
        "--metrics-history",
        type=Path,
        default=Path("harness") / "release_metrics_history.jsonl",
    )
    parser.add_argument(
        "--metrics-summary",
        type=Path,
        default=Path("harness") / "release_metrics_summary.md",
    )

    # Gate controls (same semantics as quality_metrics_pipeline).
    parser.add_argument("--max-failed-regressions", type=int, default=0)
    parser.add_argument("--max-benchmark-regressions", type=int, default=0)
    parser.add_argument("--max-mean-case-ms", type=float, default=None)
    parser.add_argument("--max-p95-case-ms", type=float, default=None)
    parser.add_argument("--require-benchmark-baseline", action="store_true")
    args = parser.parse_args()

    thresholds = GateThresholds(
        max_failed_regressions=args.max_failed_regressions,
        max_benchmark_regressions=args.max_benchmark_regressions,
        max_mean_case_ms=args.max_mean_case_ms,
        max_p95_case_ms=args.max_p95_case_ms,
        require_benchmark_baseline=args.require_benchmark_baseline,
    )

    return run_quality_gate(
        repo_root=Path("."),
        release_id=str(args.release_id),
        regression_report_path=args.regression_report,
        benchmark_report_path=args.benchmark_report,
        release_metrics_output=args.metrics_output,
        release_metrics_history=args.metrics_history,
        release_metrics_summary=args.metrics_summary,
        benchmark_baseline_path=args.benchmark_baseline,
        benchmark_iterations=args.benchmark_iterations,
        benchmark_warmup=args.benchmark_warmup,
        benchmark_max_regression_pct=args.benchmark_max_regression_pct,
        write_benchmark_baseline=bool(args.write_benchmark_baseline),
        thresholds=thresholds,
    )


if __name__ == "__main__":
    raise SystemExit(main())
