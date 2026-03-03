# Quality Harness

This repo now includes a local regression and benchmark harness for Phase 2
quality gating.

## Regression Harness

Runs deterministic scenarios across:
- file analyzer
- URL analyzer
- email analyzer

Command:

```bash
python -m harness.regression_harness
```

Optional:

```bash
python -m harness.regression_harness --output tmp/regression_report.json
```

Output:
- `harness/regression_report.json`
- process exits non-zero when any case fails

## Benchmark Harness

Runs timing benchmarks for the same scenario set and supports optional baseline
comparison.

Command:

```bash
python -m harness.benchmark_harness
```

Common options:

```bash
python -m harness.benchmark_harness --iterations 60 --warmup 10
python -m harness.benchmark_harness --write-baseline
python -m harness.benchmark_harness --max-regression-pct 25
```

Output:
- `harness/benchmark_report.json`
- `harness/benchmark_baseline.json` when `--write-baseline` is used

Behavior:
- If no baseline exists, the benchmark command reports timings and exits
  successfully.
- If a baseline exists, it fails when any case exceeds the configured slowdown
  threshold.

## Release Metrics Pipeline

Aggregates regression + benchmark outputs into one release quality artifact with
explicit gate results.

Command:

```bash
python -m harness.quality_metrics_pipeline
```

Run with fresh inputs first:

```bash
python -m harness.quality_metrics_pipeline --run-inputs
```

Common options:

```bash
python -m harness.quality_metrics_pipeline --release-id 2026.03.03
python -m harness.quality_metrics_pipeline --require-benchmark-baseline
python -m harness.quality_metrics_pipeline --max-p95-case-ms 150
```

Output:
- `harness/release_metrics.json`
- `harness/release_metrics_history.jsonl` (append-only)
- `harness/release_metrics_summary.md`

## Unified Quality Gate

Runs compile + regression + benchmark + release metrics in one command.

Command:

```bash
python -m harness.quality_gate
```

Common options:

```bash
python -m harness.quality_gate --write-benchmark-baseline
python -m harness.quality_gate --require-benchmark-baseline
python -m harness.quality_gate --max-p95-case-ms 150
```

Behavior:
- Exits non-zero if any gate fails.
- Writes regression/benchmark/metrics artifacts using the same defaults as the
  individual harness commands.
