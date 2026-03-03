"""Release quality metrics pipeline.

This module aggregates regression + benchmark outputs into one release-focused
metrics artifact and evaluates gate decisions for shipping.

Usage:
    python -m harness.quality_metrics_pipeline
    python -m harness.quality_metrics_pipeline --run-inputs
"""

from __future__ import annotations

import argparse
import json
import statistics
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path

from harness.benchmark_harness import run_benchmarks
from harness.regression_harness import run_regressions


@dataclass(frozen=True)
class GateThresholds:
    # Regression quality floor: how many failing regression cases are allowed.
    max_failed_regressions: int = 0
    # Perf quality floor: how many baseline regressions are allowed.
    max_benchmark_regressions: int = 0
    # Optional absolute latency caps (disabled when None).
    max_mean_case_ms: float | None = None
    max_p95_case_ms: float | None = None
    # Whether missing benchmark baseline should fail release gating.
    require_benchmark_baseline: bool = False


def _load_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def _write_json(path: Path, payload: dict):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")


def _write_jsonl(path: Path, payload: dict):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as f:
        f.write(json.dumps(payload))
        f.write("\n")


def _percent(numerator: int, denominator: int) -> float:
    if denominator <= 0:
        return 0.0
    return round((numerator / denominator) * 100.0, 2)


def _regression_metrics(report: dict) -> dict:
    summary = report.get("summary", {})
    cases = report.get("cases", []) or []
    total = int(summary.get("total", len(cases)))
    passed = int(summary.get("passed", sum(1 for c in cases if c.get("passed"))))
    failed = int(summary.get("failed", max(0, total - passed)))
    failed_cases = [str(case.get("case_id", "")) for case in cases if not case.get("passed")]

    observed_risk_counts = {"safe": 0, "caution": 0, "danger": 0}
    for case in cases:
        risk = str(case.get("observed_risk", "")).strip().lower()
        if risk in observed_risk_counts:
            observed_risk_counts[risk] += 1

    return {
        "total_cases": total,
        "passed_cases": passed,
        "failed_cases": failed,
        "pass_rate_pct": _percent(passed, total),
        "failed_case_ids": failed_cases,
        "observed_risk_distribution": observed_risk_counts,
    }


def _benchmark_metrics(report: dict) -> dict:
    cases = report.get("cases", []) or []
    mean_values = [float(case.get("mean_ms", 0.0)) for case in cases]
    p95_values = [float(case.get("p95_ms", 0.0)) for case in cases]
    baseline = report.get("baseline_comparison", {}) or {}
    regressions = baseline.get("regressions", []) or []
    deltas = baseline.get("deltas", []) or []

    return {
        "total_cases": len(cases),
        "mean_of_case_mean_ms": round(statistics.fmean(mean_values), 3) if mean_values else 0.0,
        "max_case_mean_ms": round(max(mean_values), 3) if mean_values else 0.0,
        "mean_of_case_p95_ms": round(statistics.fmean(p95_values), 3) if p95_values else 0.0,
        "max_case_p95_ms": round(max(p95_values), 3) if p95_values else 0.0,
        "group_summary": report.get("group_summary", {}),
        "baseline_found": bool(baseline.get("baseline_found", False)),
        "regression_count_vs_baseline": len(regressions),
        "worst_delta_pct_vs_baseline": (
            round(max(float(row.get("delta_pct", 0.0)) for row in deltas), 2)
            if deltas
            else 0.0
        ),
        "regression_cases_vs_baseline": [str(row.get("case_id", "")) for row in regressions],
    }


def _evaluate_gates(
    regression: dict,
    benchmark: dict,
    thresholds: GateThresholds,
) -> tuple[dict, list[str]]:
    warnings: list[str] = []

    regression_gate_pass = regression["failed_cases"] <= thresholds.max_failed_regressions

    baseline_found = bool(benchmark["baseline_found"])
    perf_regressions = int(benchmark["regression_count_vs_baseline"])
    if not baseline_found and thresholds.require_benchmark_baseline:
        benchmark_regression_gate_pass = False
    else:
        benchmark_regression_gate_pass = (
            perf_regressions <= thresholds.max_benchmark_regressions
        )
        if not baseline_found:
            warnings.append(
                "Benchmark baseline was not found; comparison gate ran in non-blocking mode."
            )

    mean_latency_gate_pass = True
    if thresholds.max_mean_case_ms is not None:
        mean_latency_gate_pass = benchmark["mean_of_case_mean_ms"] <= thresholds.max_mean_case_ms

    p95_latency_gate_pass = True
    if thresholds.max_p95_case_ms is not None:
        p95_latency_gate_pass = benchmark["max_case_p95_ms"] <= thresholds.max_p95_case_ms

    gates = {
        "regression_gate": {
            "passed": regression_gate_pass,
            "value": regression["failed_cases"],
            "threshold": thresholds.max_failed_regressions,
        },
        "benchmark_regression_gate": {
            "passed": benchmark_regression_gate_pass,
            "value": perf_regressions,
            "threshold": thresholds.max_benchmark_regressions,
            "baseline_found": baseline_found,
        },
        "mean_latency_gate": {
            "passed": mean_latency_gate_pass,
            "value_ms": benchmark["mean_of_case_mean_ms"],
            "threshold_ms": thresholds.max_mean_case_ms,
        },
        "p95_latency_gate": {
            "passed": p95_latency_gate_pass,
            "value_ms": benchmark["max_case_p95_ms"],
            "threshold_ms": thresholds.max_p95_case_ms,
        },
    }
    return gates, warnings


def _render_summary_markdown(payload: dict) -> str:
    gates = payload["gates"]
    regression = payload["metrics"]["regression"]
    benchmark = payload["metrics"]["benchmark"]

    def _status(flag: bool) -> str:
        return "PASS" if flag else "FAIL"

    lines = [
        "# Release Quality Metrics",
        "",
        f"- Release: `{payload['release_id']}`",
        f"- Generated: `{payload['generated_at']}`",
        f"- Overall status: **{payload['overall_status'].upper()}**",
        "",
        "## Regression",
        f"- Cases: {regression['total_cases']}",
        f"- Passed: {regression['passed_cases']}",
        f"- Failed: {regression['failed_cases']}",
        f"- Pass rate: {regression['pass_rate_pct']}%",
        "",
        "## Benchmark",
        f"- Cases: {benchmark['total_cases']}",
        f"- Mean(case mean): {benchmark['mean_of_case_mean_ms']} ms",
        f"- Max(case p95): {benchmark['max_case_p95_ms']} ms",
        f"- Baseline found: {benchmark['baseline_found']}",
        f"- Regressions vs baseline: {benchmark['regression_count_vs_baseline']}",
        "",
        "## Gates",
        f"- Regression gate: {_status(gates['regression_gate']['passed'])}",
        f"- Benchmark regression gate: {_status(gates['benchmark_regression_gate']['passed'])}",
        f"- Mean latency gate: {_status(gates['mean_latency_gate']['passed'])}",
        f"- P95 latency gate: {_status(gates['p95_latency_gate']['passed'])}",
    ]
    warnings = payload.get("warnings", [])
    if warnings:
        lines.extend(["", "## Warnings"])
        lines.extend([f"- {msg}" for msg in warnings])
    return "\n".join(lines) + "\n"


def run_quality_metrics_pipeline(
    *,
    release_id: str,
    regression_report_path: Path,
    benchmark_report_path: Path,
    output_path: Path,
    history_path: Path,
    summary_md_path: Path | None,
    thresholds: GateThresholds,
    run_inputs: bool,
    benchmark_baseline_path: Path,
    benchmark_iterations: int,
    benchmark_warmup: int,
    benchmark_max_regression_pct: float,
) -> int:
    if run_inputs:
        # Run deterministic regressions in-process and write the artifact.
        regression_payload = run_regressions()
        _write_json(regression_report_path, regression_payload)

        # Run benchmark harness to refresh benchmark artifact before aggregation.
        run_benchmarks(
            iterations=benchmark_iterations,
            warmup=benchmark_warmup,
            output_path=benchmark_report_path,
            baseline_path=benchmark_baseline_path,
            max_regression_pct=benchmark_max_regression_pct,
            write_baseline=False,
        )

    if not regression_report_path.exists():
        raise FileNotFoundError(f"Regression report not found: {regression_report_path}")
    if not benchmark_report_path.exists():
        raise FileNotFoundError(f"Benchmark report not found: {benchmark_report_path}")

    regression_report = _load_json(regression_report_path)
    benchmark_report = _load_json(benchmark_report_path)

    regression = _regression_metrics(regression_report)
    benchmark = _benchmark_metrics(benchmark_report)
    gates, warnings = _evaluate_gates(regression, benchmark, thresholds)

    overall_pass = all(gate["passed"] for gate in gates.values())
    payload = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "release_id": release_id,
        "sources": {
            "regression_report": str(regression_report_path),
            "benchmark_report": str(benchmark_report_path),
        },
        "thresholds": asdict(thresholds),
        "metrics": {
            "regression": regression,
            "benchmark": benchmark,
        },
        "gates": gates,
        "warnings": warnings,
        "overall_status": "pass" if overall_pass else "fail",
    }

    _write_json(output_path, payload)
    _write_jsonl(history_path, payload)
    if summary_md_path is not None:
        summary_md_path.parent.mkdir(parents=True, exist_ok=True)
        summary_md_path.write_text(_render_summary_markdown(payload), encoding="utf-8")

    print(f"Release metrics written: {output_path}")
    print(f"Release metrics history appended: {history_path}")
    if summary_md_path is not None:
        print(f"Release metrics summary written: {summary_md_path}")
    print(f"Overall status: {payload['overall_status'].upper()}")
    return 0 if overall_pass else 1


def _default_release_id() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate release quality metrics.")
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
        "--output",
        type=Path,
        default=Path("harness") / "release_metrics.json",
    )
    parser.add_argument(
        "--history",
        type=Path,
        default=Path("harness") / "release_metrics_history.jsonl",
    )
    parser.add_argument(
        "--summary-md",
        type=Path,
        default=Path("harness") / "release_metrics_summary.md",
    )
    parser.add_argument("--run-inputs", action="store_true")
    parser.add_argument(
        "--benchmark-baseline",
        type=Path,
        default=Path("harness") / "benchmark_baseline.json",
    )
    parser.add_argument("--benchmark-iterations", type=int, default=40)
    parser.add_argument("--benchmark-warmup", type=int, default=5)
    parser.add_argument("--benchmark-max-regression-pct", type=float, default=30.0)

    # Gate controls
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
    return run_quality_metrics_pipeline(
        release_id=str(args.release_id),
        regression_report_path=args.regression_report,
        benchmark_report_path=args.benchmark_report,
        output_path=args.output,
        history_path=args.history,
        summary_md_path=args.summary_md,
        thresholds=thresholds,
        run_inputs=bool(args.run_inputs),
        benchmark_baseline_path=args.benchmark_baseline,
        benchmark_iterations=args.benchmark_iterations,
        benchmark_warmup=args.benchmark_warmup,
        benchmark_max_regression_pct=args.benchmark_max_regression_pct,
    )


if __name__ == "__main__":
    raise SystemExit(main())
